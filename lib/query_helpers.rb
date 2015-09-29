module QueryHelpers

  def query_esc(str)
    return "" if str.nil?
    $db.escape(str)
  end

  def query_act(qry)
    begin
      $db.query(qry)
      return nil
    rescue => e
      raise QueryError.new("Query failed: #{qry}--#{e}")
    end
  end

  def query_all(qry)
    begin
      result = $db.query(qry, :symbolize_keys => true)
    rescue => e
      raise QueryError.new("Query failed: #{qry}--#{e}")
    end
    rows = []
    result.each do |row|
      rows << row
    end
    return rows
  end

  def query_one(qry)
    rows = query_all(qry)
    if rows.empty?
      return nil
    else
      return rows[0]
    end
  end

  def query_value(qry,column)
    hash = query_one(qry)
    if hash.nil?
      return nil
    else
      return hash[column]
    end
  end

end
