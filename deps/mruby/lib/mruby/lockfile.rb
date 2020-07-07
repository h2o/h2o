autoload :YAML, 'yaml'

module MRuby
  autoload :Source, 'mruby/source'

  class Lockfile
    class << self
      def enable
        @enabled = true
      end

      def disable
        @enabled = false
      end

      def enabled?
        @enabled
      end

      def build(target_name)
        instance.build(target_name)
      end

      def write
        instance.write if enabled?
      end

      def instance
        @instance ||= new("#{MRUBY_CONFIG}.lock")
      end
    end

    def initialize(filename)
      @filename = filename
    end

    def build(target_name)
      read[target_name] ||= {}
    end

    def write
      locks = {"mruby_version" => mruby}
      locks["builds"] = @builds if @builds
      File.write(@filename, YAML.dump(locks))
    end

    private

    def read
      @builds ||= if File.exist?(@filename)
                    YAML.load_file(@filename)["builds"] || {}
                  else
                    {}
                  end
    end

    def shellquote(s)
      if ENV['OS'] == 'Windows_NT'
        "\"#{s}\""
      else
        "'#{s}'"
      end
    end

    def mruby
      mruby = {
        'version' => MRuby::Source::MRUBY_VERSION,
        'release_no' => MRuby::Source::MRUBY_RELEASE_NO,
      }

      git_dir = "#{MRUBY_ROOT}/.git"
      if File.directory?(git_dir)
        mruby['git_commit'] = `git --git-dir #{shellquote(git_dir)} --work-tree #{shellquote(MRUBY_ROOT)} rev-parse --verify HEAD`.strip
      end

      mruby
    end

    enable
  end
end
