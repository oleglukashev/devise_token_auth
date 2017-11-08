module DeviseTokenAuth
  class Error < StandardError
  end

  class MissingEmailError < Error
  end

  class EmailAlreadyExistsError < Error
  end

  class EmailIsNotConfirmedError < Error
  end

  class UserNotFoundError < Error
  end

  class MissingRedirectUrlError < Error
  end

  class RedirectUrlNotAllowedError < Error
  end

  class NotAuthorizedError < Error
  end

  class PasswordNotRequiredError < Error
  end

  class PasswordIsMissingError < Error
  end

  class BadCredentialsError < Error
  end

  class InvalidTokenError < Error
  end
end
