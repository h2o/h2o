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
