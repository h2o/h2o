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
      caller_dir = File.expand_path(File.dirname(/^(.*?):\d/.match(caller.first).to_a[1]))

      if gemdir.is_a?(Hash)
        gemdir = load_special_path_gem(gemdir)
      elsif GemBox.path && gemdir.is_a?(String)
        gemdir = File.expand_path(gemdir, File.dirname(GemBox.path))
      else
        gemdir = File.expand_path(gemdir, caller_dir)
      end

      gemrake = File.join(gemdir, "mrbgem.rake")

      fail "Can't find #{gemrake}" unless File.exist?(gemrake)
      Gem.current = nil
      load gemrake
      return nil unless Gem.current

      Gem.current.dir = gemdir
      Gem.current.build = self.is_a?(MRuby::Build) ? self : MRuby::Build.current
      Gem.current.build_config_initializer = block
      gems << Gem.current

      cxx_srcs = ['src', 'test', 'tools'].map do |subdir|
        Dir.glob("#{Gem.current.dir}/#{subdir}/*.{cpp,cxx,cc}")
      end.flatten
      enable_cxx_exception unless cxx_srcs.empty?

      Gem.current
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
          FileUtils.mkdir_p mgem_list_dir
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

        if File.exist?(gemdir)
          if $pull_gems
            git.run_pull gemdir, url
          else
            gemdir
          end
        else
          options = [params[:options]] || []
          options << "--recursive"
          options << "--branch \"#{branch}\""
          options << "--depth 1" unless params[:checksum_hash]
          FileUtils.mkdir_p "#{gem_clone_dir}"
          git.run_clone gemdir, url, options
        end

        if params[:checksum_hash]
          # Jump to the specified commit
          git.run_checkout gemdir, params[:checksum_hash]
        else
          # Jump to the top of the branch
          git.run_checkout gemdir, branch if $pull_gems
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
