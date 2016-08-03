# Copyright (c) 2016 DeNA Co., Ltd., Ichito Nagata
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
class LRUCache

  def initialize(capacity)
    @capacity = capacity
    @head = nil
    @tail = nil
    @nodes = {}
    raise "capacity must not be negative" if @capacity < 0
  end

  def set(key, value)
    if ! @head
      @nodes[key] = @head = @tail = [ nil, nil, key, value ]
    elsif node = @nodes[key]
      move_to_head(node)
      node[3] = value
    else
      node = [ nil, @head, key, value ]
      @head[0] = node
      @nodes[key] = @head = node
    end

    while @nodes.size > @capacity do
      @nodes.delete(@tail[2])
      @tail = @tail[0]
      if @tail
        @tail[1] = nil
      else
        @head = nil
        break
      end
    end

    return value
  end

  def get(key)
    node = @nodes[key]
    return nil unless node
    move_to_head(node)
    return node[3]
  end

  private

  def move_to_head(node)
    if node == @head
      return
    elsif node == @tail
      @tail = @tail[0]
      @tail[1] = nil
    end
    node[0][1] = node[1]
    node[1][0] = node[0] if node[1]
    node[0] = nil
    node[1] = @head
    @head[0] = node
    @head = node
  end

end
