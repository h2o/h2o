class File
  module Constants
    FNM_SYSCASE  = 0
    FNM_NOESCAPE = 1
    FNM_PATHNAME = 2
    FNM_DOTMATCH = 4
    FNM_CASEFOLD = 8
  end
end

class File
  include File::Constants
end
