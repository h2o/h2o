module H2O

  @@handler_validators = []

  def self.validate_handler(handler)
    @@handler_validators.each do |validator|
      # will raise exception if handler is not valid
      validator.call(handler)
    end
  end

  def self.add_handler_validator(validator)
    @@handler_validators << validator
  end

end
