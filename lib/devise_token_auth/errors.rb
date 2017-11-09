module DeviseTokenAuth
  class Error < StandardError
    attr_reader :http_status

    def initialize(status: :internal_server_erro)
      @http_status = status
    end
  end

  class MissingEmailError < Error
    def initialize
      super(status: :unauthorized)
    end
  end

  class EmailAlreadyExistsError < Error
    def initialize
      super(status: :unprocessable_entity)
    end
  end

  class EmailIsNotConfirmedError < Error
    def initialize
      super(status: :unauthorized)
    end
  end

  class UserNotFoundError < Error
    def initialize
      super(status: :not_found)
    end
  end

  class MissingRedirectUrlError < Error
    def initialize
      super(status: :unauthorized)
    end
  end

  class RedirectUrlNotAllowedError < Error
    def initialize
      super(status: :unprocessable_entity)
    end
  end

  class NotAuthorizedError < Error
    def initialize
      super(status: :unauthorized)
    end
  end

  class PasswordNotRequiredError < Error
    def initialize
      super(status: :unprocessable_entity)
    end
  end

  class PasswordIsMissingError < Error
    def initialize
      super(status: :unprocessable_entity)
    end
  end

  class BadCredentialsError < Error
    def initialize
      super(status: :unauthorized)
    end
  end

  class InvalidTokenError < Error
    def initialize
      super(status: :unauthorized)
    end
  end

  class UidNotProvidedError < Error
    def initialize
      super(status: :not_acceptable)
    end
  end

  class ClientNotProvidedError < Error
    def initialize
      super(status: :not_acceptable)
    end
  end

  class WrongRefreshTokenError < Error
    def initialize
      super(status: :unauthorized)
    end
  end
end
