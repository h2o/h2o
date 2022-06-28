CI_VERSION = '0.7'.freeze
CI_BASE = 'ubuntu:16.10'.freeze
CI_COMPILERS = ['gcc-4.7',
                'gcc-4.8',
                'gcc-4.9',
                'gcc-5',
                'gcc-6',
                'clang-3.5',
                'clang-3.6',
                'clang-3.7',
                'clang-3.8',
                'clang-3.9'].freeze

def ci_image_tag(compiler)
  compiler.tr('+', 'c').delete('-').delete('.')
end

def ci_docker_tag(compiler)
  tag = ci_image_tag(compiler)
  "registry.gitlab.com/dabroz/mruby:#{tag}_#{CI_VERSION}"
end

def run_cmd(cmd)
  puts cmd
  raise 'error' unless system cmd
end

desc 'recreate docker images for GitLab builds'
task :gitlab_dockers do
  CI_COMPILERS.each do |compiler|
    tag = ci_image_tag(compiler)
    filename = "Dockerfile.#{tag}"
    File.open(filename, 'wb') do |f|
      f << "# #{compiler} - #{tag}\n"
      f << "FROM #{CI_BASE}\n"
      f << "RUN apt-get update && apt-get install -y git ruby2.3 ruby2.3-dev bison\n"
      f << "RUN apt-get update && apt-get install -y binutils manpages\n"
      f << "RUN apt-get update && apt-get install -y #{compiler}\n"
      if compiler['gcc']
        f << "RUN apt-get update && apt-get install -y libx32#{compiler}-dev\n"
        f << "RUN apt-get update && apt-get install --no-install-recommends -y #{compiler}-multilib\n"
      end
      f << "RUN dpkg --add-architecture i386\n"
      f << "RUN apt-get update && apt-get install -y linux-libc-dev:i386\n"
      if compiler['clang']
        f << "RUN apt-get update && apt-get install --no-install-recommends -y libc6-dev-i386\n"
        f << "RUN apt-get update && apt-get install -y gcc gcc-multilib\n"
      end
    end
    docker_tag = ci_docker_tag(compiler)
    cmd1 = "docker build -t #{docker_tag} -f #{filename} ."
    cmd2 = "docker push #{docker_tag}"
    run_cmd cmd1
    run_cmd cmd2
    File.delete(filename)
  end
end

desc 'create build configurations and update .gitlab-ci.yml'
task :gitlab_config do
  require 'yaml'

  configs = []
  [true, false].each do |mode_32|
    ['', 'MRB_USE_FLOAT'].each do |float_conf|
      ['', 'MRB_NAN_BOXING', 'MRB_WORD_BOXING'].each do |boxing_conf|
        ['', 'MRB_UTF8_STRING'].each do |utf8_conf|
          next if (float_conf == 'MRB_USE_FLOAT') && (boxing_conf == 'MRB_NAN_BOXING')
          next if (int_conf == 'MRB_INT64') && (boxing_conf == 'MRB_NAN_BOXING')
          next if (int_conf == 'MRB_INT64') && (boxing_conf == 'MRB_WORD_BOXING') && mode_32
          env = [float_conf, int_conf, boxing_conf, utf8_conf].map do |conf|
            conf == '' ? nil : "-D#{conf}=1"
          end.compact.join(' ')
          bit = mode_32 ? '-m32 ' : ''
          _info = ''
          _info += mode_32 ? '32bit ' : '64bit '
          _info += float_conf['USE'] ? 'float ' : ''
          _info += int_conf['16'] ? 'int16 ' : ''
          _info += int_conf['64'] ? 'int64 ' : ''
          _info += boxing_conf['NAN'] ? 'nan ' : ''
          _info += boxing_conf['WORD'] ? 'word ' : ''
          _info += utf8_conf['UTF8'] ? 'utf8 ' : ''
          _info = _info.gsub(/ +/, ' ').strip.tr(' ', '_')
          configs << { '_info' => _info, 'CFLAGS' => "#{bit}#{env}", 'LDFLAGS' => bit.strip.to_s }
        end
      end
    end
  end
  path = './.gitlab-ci.yml'
  data = YAML.load_file(path)
  data.keys.select do |key|
    key.start_with? 'Test'
  end.each do |key|
    data.delete(key)
  end
  CI_COMPILERS.each do |compiler|
    configs.each do |config|
      name = "Test #{compiler} #{config['_info']}"
      hash = {
        'CC' => compiler,
        'CXX' => compiler.gsub('gcc', 'g++').gsub('clang', 'clang++'),
        'LD' => compiler
      }
      hash = hash.merge(config)
      hash.delete('_info')
      data[name] = {
        'stage' => 'test',
        'image' => ci_docker_tag(compiler),
        'variables' => hash,
        'script' => 'env; rake --verbose all test'
      }
    end
  end
  File.open(path, 'w') { |f| YAML.dump(data, f) }
end
