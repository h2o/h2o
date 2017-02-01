module H2O

  class HttpRequest
    def join
      if !@resp
        @resp = _h2o__http_join_response(self)
      end
      @resp
    end
    def _set_response(resp)
      @resp = resp
    end
  end

  class HttpInputStream
    def each
      while c = _h2o__http_fetch_chunk(self)
        yield c
      end
    end
    def join
      s = ""
      each do |c|
        s << c
      end
      s
    end
  end

end
