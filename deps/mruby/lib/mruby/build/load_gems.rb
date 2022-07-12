require 'yaml'

module MRuby
  module LoadGems

    def gembox(gemboxfile)
      gembox = File.expand_path("#{gemboxfile}.gembox", "#{MRUBY_ROOT}/mrbgems")
      fail "Can't find gembox '#{gembox}'" unless File.exist?(gembox)

      GemBox.config = self
      GemBox.path = gembox

      instance_eval File.read(gembox)

      GemBox.path = nil
    end

    def gem(gem_src, &block)

      caller_dir = File.expand_path(File.dirname(caller(1,1)[0][/^(.*?):\d/,1]))

      gem_src = {gemdir: gem_src} if gem_src.is_a? String

      @gem_checkouts ||= {}
      checkout = GemLoader
                   .new(self, caller_dir, @gem_checkouts, **gem_src)
                   .fetch!
      return nil unless checkout
      @gem_checkouts[checkout.gemdir] = checkout

      # Load the gem's rakefile
      gemrake = File.join(checkout.full_gemdir, "mrbgem.rake")
      fail "Can't find #{gemrake}" unless File.exist?(gemrake)

      Gem.current = nil
      load gemrake
      return nil unless Gem.current
      current = Gem.current

      # Add it to gems
      current.dir = checkout.full_gemdir
      current.build = self.is_a?(MRuby::Build) ? self : MRuby::Build.current
      current.build_config_initializer = block
      gems << current

      cxx_srcs = Dir.glob("#{current.dir}/{src,test,tools}/*.{cpp,cxx,cc}")
      enable_cxx_exception unless cxx_srcs.empty?

      current
    end


    # Class to represent the relationship between a gem dependency and
    # its remote repository (if any).
    class GemCheckout
      attr_reader :gemdir, :repo, :branch, :commit

      def initialize(gemdir, repo, branch, commit, canonical, path = nil)
        @gemdir = gemdir            # Working copy of the gem
        @path = path                # Path to gem relative to checkout

        @repo =  repo               # Remote gem repo
        @branch = branch            # Branch to check out
        @commit = commit            # Commit-id to use

        @canonical = canonical      # This is the One True checkout
      end

      def full_gemdir
        return @gemdir unless @path
        return File.join(@gemdir, @path)
      end

      def canonical?()  return @canonical;                  end
      def git?()        return !!@repo;                     end
      def gemname()     return File.basename(@gemdir);      end

      def hash()
        return [@gemdir, @repo, @branch, @commit, @canonical, @path].hash
      end

      def ==(other)
        return @gemdir == other.gemdir &&
          @repo == other.repo &&
          @branch == other.branch &&
          @commit == other.commit &&
          @canonical == other.canonical? &&
          full_gemdir == other.full_gemdir
      end
      alias_method :eql?, :==

      def to_s
        desc = @gemdir
        desc += " -> #{@repo}/#{@branch}" if git?
        desc += "/#{commit}" if commit
        return desc
      end
    end

    # Class to decode the argument set given to 'MRuby::Build::gem',
    # and git-clone+git-checkout the sources if needed.
    class GemLoader
      def initialize(build,
                     build_config_dir,      # Parent dir. of build_config
                     gem_checkouts,         # Hash of existing checkouts

                     # Git repo:
                     git: nil,
                     branch: "master",
                     checksum_hash: nil,
                     options: [],
                     path: nil,     # path to root relative to gem checkout

                     # Git repo on GitHub
                     github: nil,

                     # Git repo on BitBucket
                     bitbucket: nil,
                     method: nil,

                     # mgem entry
                     mgem: nil,

                     # Core package
                     core: nil,

                     # Local file(s)
                     gemdir: nil,

                     # Related flags:
                     canonical: false   # Ignore subsequent checkout of this gem
                    )
        # Tolerate a single string option
        options = [options] unless options.is_a? Array

        @build = build
        @build_config_dir = build_config_dir
        @gem_checkouts = gem_checkouts
        @canonical = canonical

        @git = git
        @path = path
        @branch = branch
        @checksum_hash = checksum_hash
        @options = options
        @canonical = canonical

        @github = github

        @bitbucket = bitbucket
        @method = method

        @mgem = mgem
        @core = core
        @gemdir = gemdir


        actions = [git, github, bitbucket, mgem, core, gemdir]
        fail("Need to set exactly ONE of git, github, bitbucket, mgem, core, " +
             "or gemdir") unless actions.compact.size == 1
      end

      # Retrieve the repo and return the details in a GemCheckout
      # object or nil if nothing needed to be done.
      def fetch!
        return fromGemdir!              if @gemdir
        return fromCore!                if @core
        return fromGitHub!              if @github
        return fromBitBucket!           if @bitbucket

        return fromMGem!                if @mgem

        return fromGit!(@git, @branch)  if @git

        # Shouldn't be reachable, but...
        fail "Invalid gem configuration!"
      end

      private

      #
      # Local Paths
      #

      def fromGemdir!
        gem_src = @gemdir

        # If @gemdir is a relative path, we first convert it to an
        # absolute path; this depends on circumstances.
        if MRuby::GemBox.path
          # If GemBox.path is set, it means that this fetch operation is
          # happening as part of a gembox evaluation and we use the
          # gembox's path as the starting point.
          gem_src = File.expand_path(gem_src, File.dirname(MRuby::GemBox.path))
        else
          # Otherwise, we use the path to the build_config.rb file that
          # requested this gem.  This path was extracted earlier and
          # stored in @build_config_dir via the second argument of
          # 'initialize'.
          root_dir = @build_config_dir

          # And we default to the repo root if the file is one of the
          # stock configs in build_config/.
          root_dir = MRUBY_ROOT if root_dir == "#{MRUBY_ROOT}/build_config"

          gem_src = File.expand_path(gem_src, root_dir)
        end

        return GemCheckout.new(gem_src, nil, nil, nil, @canonical)
      end

      def fromCore!
        return GemCheckout.new("#{@build.root}/mrbgems/#{@core}", nil, nil,
                               nil, @canonical)
      end


      #
      # Git forges
      #

      def fromGitHub!
        url = "https://github.com/#{@github}.git"
        return fromGit!(url, @branch)
      end

      def fromBitBucket!
        if @method == "ssh"
          url = "git@bitbucket.org:#{@bitbucket}.git"
        else
          url = "https://bitbucket.org/#{@bitbucket}.git"
        end

        return fromGit!(url, @branch)
      end


      #
      # mgem file
      #

      def fromMGem!
        mgem = fetchMGem(@mgem)

        url = mgem['repository']
        branch = mgem['branch'] || @branch

        return fromGit!(url, branch)
      end

      # Fetch the contents of the named mgem item. Will clone the
      # mgem-list repo if not present
      def fetchMGem(mgem)
        list_dir = "#{@build.gem_clone_dir}/mgem-list"
        url = 'https://github.com/mruby/mgem-list.git'

        git_clone_dependency(url, list_dir, nil, 'master')

        conf_path = "#{list_dir}/#{mgem}.gem"
        conf_path = "#{list_dir}/mruby-#{mgem}.gem" unless
          File.exist? conf_path
        fail "mgem not found: #{mgem}" unless File.exist? conf_path

        conf = YAML.load File.read conf_path
        fail "unknown mgem protocol: #{conf['protocol']}" if
          conf['protocol'] != 'git'

        return conf
      end


      #
      # Git checkouts
      #

      def fromGit!(url, branch)
        repo_dir = "#{@build.gem_clone_dir}/" +
                   "#{url.match(/([-\w]+)(\.[-\w]+|)$/).to_a[1]}"
        commit = @checksum_hash

        return nil if skip_this?(url, repo_dir, branch, commit)

        # If there's a lockfile entry for this repo AND the user hasn't
        # specified a specific commit ID, we use the locked branch and
        # commit.
        lock = @build.locks[url] if @build.lock_enabled?
        if !commit && lock
          branch = lock['branch']
          commit = lock['commit']
        end

        # Clone the dependency (if needed) and checkout the expected
        # revision.
        git_clone_dependency(url, repo_dir, commit, branch)
        git_checkout_dependency(repo_dir, commit, branch)

        # Set the lockfile entry if enabled
        if @build.lock_enabled?
          @build.gem_dir_to_repo_url[repo_dir] = url
          @build.locks[url] = {
            'url' => url,
            'branch' => @build.git.current_branch(repo_dir),
            'commit' => @build.git.commit_hash(repo_dir),
          }
        end

        return GemCheckout.new(repo_dir, url, branch, commit, @canonical,@path)
      end


      # Test if this repo can be skipped.  This will happen if it's
      # already in @gem_checkouts and EITHER it is identical (same
      # url, branch, commit-ID and subdirectory path) as the current
      # checkout OR its "canonical" flag is true.  If it's in
      # @gem_checkouts and neither of these conditions is true, that's
      # a fatal error; it means there are multiple incompatible
      # versions of this gem to be checked out into this directory.
      #
      # Otherwise, returns false.
      def skip_this?(url, repo_dir, branch, commit)
        prev = @gem_checkouts[repo_dir]
        return false unless prev

        # Canonical declarations must precede all others.
        fail("Attempted to re-declare #{prev.gemname} as canonical!\n" +
             "('canonical' can only be used on its first declaration.)") if
          prev && @canonical

        # If prev is canonical, we can ignore this
        if prev.canonical?
          puts "Found canonical #{prev.gemname}; skipping this one."
          return true
        end

        # If this checkout is identical to the current one, we can skip it.
        candidate = GemCheckout.new(repo_dir, url, branch, commit, @canonical,
                                    @path)
        if prev == candidate
          puts "Found duplicate checkout for #{repo_dir}; ignoring."
          return true
        end

        # Otherwise, we have a checkout conflict.  This is an error.
        fail "Conflicting gem definitions for '#{repo_dir}':\n" +
             "  #{candidate}\n" +
             "  #{prev}\n"
      end


      # Retrieve a git repo if it's not present.  Return
      # [path_to_checkout, did_clone]
      def git_clone_dependency(url, repo_dir, commit, branch)
        return if
          File.exist?(repo_dir) && File.exist?(File.join(repo_dir, '.git'))

        FileUtils.mkdir_p repo_dir

        options = @options.dup
        options << "--recursive"
        options << "--branch \"#{branch}\""
        options << "--depth 1" unless commit

        @build.git.run_clone repo_dir, url, options
      end

      def git_checkout_dependency(repo_dir, commit, branch)
        @build.git.run_checkout_detach(repo_dir, commit)
      end
    end

    def enable_gems?
      !@gems.empty?
    end
  end # LoadGems
end # MRuby
