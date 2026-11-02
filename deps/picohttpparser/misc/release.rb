#!/usr/bin/env ruby

require "optparse"
require "shellwords"
require "tmpdir"
require "fileutils"

class ReleaseError < StandardError
end

def run_command(*args, capture: false, allow_failure: false, chdir: nil, env: {})
  command = args.flatten.map(&:to_s)
  success = nil
  output = nil

  Dir.chdir(chdir || Dir.pwd) do
    if capture
      output = IO.popen(env, command, err: [:child, :out], &:read)
      success = $?.success?
    else
      success = system(env, *command)
    end
  end

  return output if capture && (success || allow_failure)
  return success if !capture && (success || allow_failure)

  raise ReleaseError, "command failed: #{command.shelljoin}"
end

def git(*args, **kwargs)
  run_command("git", *args, **kwargs)
end

def git_success?(*args, chdir: nil, env: {})
  command = ["git", *args].flatten.map(&:to_s)
  Dir.chdir(chdir || Dir.pwd) do
    system(env, *command, out: File::NULL, err: File::NULL)
  end
end

def parse_options
  options = {
    header: "picohttpparser.h",
    author_name: "Kazuho Oku",
    author_email: "kazuhooku+github-actions@gmail.com",
    push: false
  }

  parser = OptionParser.new do |opts|
    opts.banner = "usage: misc/release.rb --source-branch BRANCH --release-branch BRANCH --tag-prefix PREFIX"
    opts.separator "                        [--remote NAME] [--header PATH] [--author-name NAME]"
    opts.separator "                        [--author-email EMAIL] [--push]"

    opts.on("--source-branch BRANCH") { |value| options[:source_branch] = value }
    opts.on("--release-branch BRANCH") { |value| options[:release_branch] = value }
    opts.on("--tag-prefix PREFIX") { |value| options[:tag_prefix] = value }
    opts.on("--remote NAME") { |value| options[:remote] = value }
    opts.on("--header PATH") { |value| options[:header] = value }
    opts.on("--author-name NAME") { |value| options[:author_name] = value }
    opts.on("--author-email EMAIL") { |value| options[:author_email] = value }
    opts.on("--push") { options[:push] = true }
  end

  parser.parse!

  %i[source_branch release_branch tag_prefix].each do |key|
    raise ReleaseError, "--#{key.to_s.tr('_', '-')} is required" if options[key].to_s.empty?
  end

  options
end

def fetch_branch(remote, branch)
  if remote.to_s.empty?
    ok = git_success?("rev-parse", "--verify", "#{branch}^{commit}")
    raise ReleaseError, "branch not found: #{branch}" unless ok
    return
  end

  git("fetch", remote, "refs/heads/#{branch}:refs/remotes/#{remote}/#{branch}")
end

def git_show(ref, path)
  git("show", "#{ref}:#{path}", capture: true)
end

def parse_header(header_text, header_path, ref)
  major = header_text[/^#define PICOHTTPPARSER_VERSION_MAJOR (\d+)$/, 1]
  version = header_text[/^#define PICOHTTPPARSER_VERSION "([^"]+)"$/, 1]

  raise ReleaseError, "could not parse PICOHTTPPARSER_VERSION_MAJOR from #{header_path} on #{ref}" if major.nil?
  unless version == "#{major}.dev"
    raise ReleaseError, "expected #{header_path} on #{ref} to carry a #{major}.dev version string"
  end

  major
end

def next_minor(tag_prefix)
  latest = 0
  git("tag", "-l", "#{tag_prefix}*", capture: true).lines.each do |line|
    tag = line.strip
    suffix = tag.delete_prefix(tag_prefix)
    next unless /\A\d+\z/.match?(suffix)

    value = suffix.to_i
    latest = value if value > latest
  end

  latest + 1
end

def rewrite_header(path, version, major, minor)
  text = File.read(path)
  text = text.sub(/^#define PICOHTTPPARSER_VERSION ".*"$/, "#define PICOHTTPPARSER_VERSION \"#{version}\"")
  text = text.sub(/^#define PICOHTTPPARSER_VERSION_MAJOR \d+$/, "#define PICOHTTPPARSER_VERSION_MAJOR #{major}")
  text = text.sub(/^#define PICOHTTPPARSER_VERSION_MINOR \d+.*$/, "#define PICOHTTPPARSER_VERSION_MINOR #{minor}")
  File.write(path, text)

  rewritten = File.read(path)
  unless rewritten.match?(%r{^#define PICOHTTPPARSER_VERSION "#{Regexp.escape(version)}"$}) &&
         rewritten.match?(%r{^#define PICOHTTPPARSER_VERSION_MAJOR #{major}$}) &&
         rewritten.match?(%r{^#define PICOHTTPPARSER_VERSION_MINOR #{minor}$})
    raise ReleaseError, "failed to rewrite version macros in #{path}"
  end
end

def git_env(options)
  {
    "GIT_AUTHOR_NAME" => options[:author_name],
    "GIT_AUTHOR_EMAIL" => options[:author_email],
    "GIT_COMMITTER_NAME" => options[:author_name],
    "GIT_COMMITTER_EMAIL" => options[:author_email]
  }
end

def main
  options = parse_options
  repo_root = git("rev-parse", "--show-toplevel", capture: true).strip

  fetch_branch(options[:remote], options[:source_branch])

  if options[:remote]
    git("fetch", "--tags", options[:remote])
    git("fetch", options[:remote], "refs/heads/#{options[:release_branch]}:refs/remotes/#{options[:remote]}/#{options[:release_branch]}",
        allow_failure: true)
    source_ref = "refs/remotes/#{options[:remote]}/#{options[:source_branch]}"
    release_ref = "refs/remotes/#{options[:remote]}/#{options[:release_branch]}"
  else
    source_ref = options[:source_branch]
    release_ref = options[:release_branch]
  end

  major = parse_header(git_show(source_ref, options[:header]), options[:header], source_ref)
  minor = next_minor(options[:tag_prefix])
  version = "#{major}.#{minor}"
  tag = "#{options[:tag_prefix]}#{minor}"

  worktree = Dir.mktmpdir("picohttpparser-release.")
  begin
    git("-C", repo_root, "worktree", "add", "--detach", worktree, source_ref)

    release_exists = git_success?("rev-parse", "--verify", "#{release_ref}^{commit}", chdir: worktree)
    if release_exists
      git("checkout", "-B", options[:release_branch], release_ref, chdir: worktree)
    else
      git("checkout", "-b", options[:release_branch], source_ref, chdir: worktree)
    end

    if release_exists && git_success?("merge-base", "--is-ancestor", source_ref, "HEAD", chdir: worktree)
      puts "release branch already contains #{source_ref}; nothing to do"
      return
    end

    if release_exists
      git("merge", "--no-ff", "-X", "theirs", "--no-edit", source_ref, chdir: worktree, env: git_env(options))
    end

    rewrite_header(File.join(worktree, options[:header]), version, major, minor)

    raise ReleaseError, "tag already exists: #{tag}" if git_success?("rev-parse", "--verify", "#{tag}^{tag}", chdir: worktree)

    git("add", options[:header], chdir: worktree)
    git("commit", "-m", "release #{tag}", "-m", "Generated from #{options[:source_branch]} by release automation.",
        chdir: worktree, env: git_env(options))
    git("tag", "-a", tag, "-m", "release #{tag}", chdir: worktree, env: git_env(options))

    if options[:push]
      raise ReleaseError, "--push requires --remote" if options[:remote].to_s.empty?

      git("push", options[:remote], options[:release_branch], chdir: worktree)
      git("push", options[:remote], tag, chdir: worktree)
    end

    puts "created #{tag} on #{options[:release_branch]}"
  ensure
    git("-C", repo_root, "worktree", "remove", "--force", worktree, allow_failure: true)
    FileUtils.remove_entry(worktree, true) if File.exist?(worktree)
  end
end

main
