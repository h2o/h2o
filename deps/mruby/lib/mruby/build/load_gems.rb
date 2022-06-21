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

    def gem(gemdir, &block)
      if gemdir.is_a?(Hash)
        gemdir = load_special_path_gem(gemdir)
      elsif GemBox.path
        gemdir = File.expand_path(gemdir, File.dirname(GemBox.path))
      else
        caller_dir = File.expand_path(File.dirname(caller(1,1)[0][/^(.*?):\d/,1]))
        if caller_dir == "#{MRUBY_ROOT}/build_config"
          caller_dir = MRUBY_ROOT
        end
        gemdir = File.expand_path(gemdir, caller_dir)
      end

      gemrake = File.join(gemdir, "mrbgem.rake")

      fail "Can't find #{gemrake}" unless File.exist?(gemrake)
      Gem.current = nil
      load gemrake
      return nil unless Gem.current
      current = Gem.current

      current.dir = gemdir
      current.build = self.is_a?(MRuby::Build) ? self : MRuby::Build.current
      current.build_config_initializer = block
      gems << current

      cxx_srcs = Dir.glob("#{current.dir}/{src,test,tools}/*.{cpp,cxx,cc}")
      enable_cxx_exception unless cxx_srcs.empty?

      current
    end

    def load_special_path_gem(params)
      if params[:github]
        params[:git] = "https://github.com/#{params[:github]}.git"
      elsif params[:bitbucket]
        if params[:method] == "ssh"
          params[:git] = "git@bitbucket.org:#{params[:bitbucket]}.git"
        else
          params[:git] = "https://bitbucket.org/#{params[:bitbucket]}.git"
        end
      elsif params[:mgem]
        mgem_list_dir = "#{gem_clone_dir}/mgem-list"
        mgem_list_url = 'https://github.com/mruby/mgem-list.git'
        if File.exist? mgem_list_dir
          git.run_pull mgem_list_dir, mgem_list_url if $pull_gems
        else
          mkdir_p mgem_list_dir
          git.run_clone mgem_list_dir, mgem_list_url, "--depth 1"
        end

        require 'yaml'

        conf_path = "#{mgem_list_dir}/#{params[:mgem]}.gem"
        conf_path = "#{mgem_list_dir}/mruby-#{params[:mgem]}.gem" unless File.exist? conf_path
        fail "mgem not found: #{params[:mgem]}" unless File.exist? conf_path
        conf = YAML.load File.read conf_path

        fail "unknown mgem protocol: #{conf['protocol']}" if conf['protocol'] != 'git'
        params[:git] = conf['repository']
        params[:branch] = conf['branch'] if conf['branch']
      end

      if params[:core]
        gemdir = "#{root}/mrbgems/#{params[:core]}"
      elsif params[:git]
        url = params[:git]
        gemdir = "#{gem_clone_dir}/#{url.match(/([-\w]+)(\.[-\w]+|)$/).to_a[1]}"

        # by default the 'master' branch is used
        branch = params[:branch] ? params[:branch] : 'master'

        lock = locks[url] if lock_enabled?

        if File.exist?(gemdir)
          if $pull_gems
            # Jump to the top of the branch
            git.run_checkout gemdir, branch
            git.run_pull gemdir, url
          elsif params[:checksum_hash]
            git.run_checkout_detach gemdir, params[:checksum_hash]
          elsif lock
            git.run_checkout_detach gemdir, lock['commit']
          end
        else
          options = [params[:options]] || []
          options << "--recursive"
          options << "--branch \"#{branch}\""
          options << "--depth 1" unless params[:checksum_hash] || lock
          mkdir_p "#{gem_clone_dir}"
          git.run_clone gemdir, url, options

          # Jump to the specified commit
          if params[:checksum_hash]
            git.run_checkout_detach gemdir, params[:checksum_hash]
          elsif lock
            git.run_checkout_detach gemdir, lock['commit']
          end
        end

        if lock_enabled?
          @gem_dir_to_repo_url[gemdir] = url unless params[:path]
          locks[url] = {
            'url' => url,
            'branch' => git.current_branch(gemdir),
            'commit' => git.commit_hash(gemdir),
          }
        end

        gemdir << "/#{params[:path]}" if params[:path]
      elsif params[:path]
        require 'pathname'
        gemdir = Pathname.new(params[:path]).absolute? ? params[:path] : "#{root}/#{params[:path]}"
      else
        fail "unknown gem option #{params}"
      end

      gemdir
    end

    def enable_gems?
      !@gems.empty?
    end
  end # LoadGems
end # MRuby
