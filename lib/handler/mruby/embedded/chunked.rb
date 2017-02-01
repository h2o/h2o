module Kernel

  def _h2o_chunked_proc_each_to_fiber()
    Proc.new do |src|
      fiber = Fiber.new do
        src.each do |chunk|
          _h2o_send_chunk(chunk)
        end
        _h2o_send_chunk_eos()
      end
      fiber.resume
    end
  end

end
