module DeviseTokenAuth
  class TokensController < DeviseTokenAuth::ApplicationController
    skip_before_action :assert_is_devise_resource!, only: [:update]

    def update
      set_user_by_refresh_token

      yield @resource if block_given?

      refresh_token_header = DeviseTokenAuth.headers_names[:"refresh-token"]
      response.headers.merge!({ refresh_token_header => @new_refresh_token })

      render_new_token_success
    end

    protected

    def render_new_token_success
      render json: resource_data(resource_json: @resource.token_validation_response)
    end

    def set_user_by_refresh_token
      @refresh_token = params[:refresh_token]

      uid_name = DeviseTokenAuth.headers_names[:'uid']
      client_name = DeviseTokenAuth.headers_names[:'client']

      uid        = request.headers[uid_name] || params[uid_name]
      @client_id ||= request.headers[client_name] || params[client_name]

      raise UidNotProvidedError unless uid
      raise ClientNotProvidedError unless @client_id

      user = uid && resource_class.find_by(uid: uid)

      if user && user.valid_refresh_token?(@refresh_token, @client_id)
        @resource = user

        @token = SecureRandom.urlsafe_base64(nil, false)
        @new_refresh_token = SecureRandom.urlsafe_base64(nil, false)

        @resource.tokens[@client_id] = {
          token: BCrypt::Password.create(@token),
          expiry: (Time.current + @resource.token_lifespan).to_i,
          refresh_token: BCrypt::Password.create(@new_refresh_token),
          refresh_token_expiry: (Time.current + DeviseTokenAuth.refresh_token_lifespan).to_i
        }

        @resource.save
      else
        # zero all values previously set values
        @client_id = nil
        @resource = nil
        @refresh_token = nil
        raise WrongRefreshTokenError
      end
    end
  end
end
