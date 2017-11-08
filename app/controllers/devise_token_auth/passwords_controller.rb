module DeviseTokenAuth
  class PasswordsController < DeviseTokenAuth::ApplicationController
    before_action :set_user_by_token, :only => [:update]
    skip_after_action :update_auth_header, :only => [:create, :edit]

    # this action is responsible for generating password reset tokens and
    # sending emails
    def create
      raise MissingEmailError unless resource_params[:email]

      # give redirect value from params priority
      @redirect_url = params[:redirect_url]

      # fall back to default value if provided
      @redirect_url ||= DeviseTokenAuth.default_password_reset_url

      raise MissingRedirectUrlError unless @redirect_url

      # if whitelist is set, validate redirect_url against whitelist
      if DeviseTokenAuth.redirect_whitelist
        unless DeviseTokenAuth::Url.whitelisted?(@redirect_url)
          raise RedirectUrlNotAllowedError
        end
      end

      @email = get_case_insensitive_field_from_resource_params(:email)
      @resource = find_resource(:uid, @email)

      raise UserNotFoundError unless @resource

      yield @resource if block_given?

      @resource.send_reset_password_instructions({
        email: @email,
        provider: 'email',
        redirect_url: @redirect_url,
        client_config: params[:config_name]
      })

      render json: resource_data, status: :created
    end

    # this is where users arrive after visiting the password reset confirmation link
    def edit
      # if a user is not found, return nil
      @resource = resource_class.with_reset_password_token(
        resource_params[:reset_password_token]
      )

      raise ActionController::RoutingError.new('Not Found') unless @resource

      client_id  = SecureRandom.urlsafe_base64(nil, false)
      token      = SecureRandom.urlsafe_base64(nil, false)
      token_hash = BCrypt::Password.create(token)
      expiry     = (Time.current + @resource.token_lifespan).to_i

      @resource.tokens[client_id] = {
        token:  token_hash,
        expiry: expiry
      }

      # ensure that user is confirmed
      @resource.skip_confirmation! if @resource.devise_modules.include?(:confirmable) && !@resource.confirmed_at

      # allow user to change password once without current_password
      @resource.allow_password_change = true

      @resource.save!

      yield @resource if block_given?

      redirect_header_options = { reset_password: true }
      redirect_headers = build_redirect_headers(
        token,
        client_id,
        redirect_header_options
      )

      redirect_to(@resource.build_auth_url(params[:redirect_url], redirect_headers))
    end

    def update
      # make sure user is authorized
      raise NotAuthorizedError unless @resource

      # make sure account doesn't use oauth2 provider
      unless @resource.provider == 'email'
        raise PasswordNotRequiredError
      end

      # ensure that password params were sent
      unless password_resource_params[:password] && password_resource_params[:password_confirmation]
        raise PasswordIsMissingError
      end

      unless @resource.send(resource_update_method, password_resource_params)
        raise ActiveRecord::RecordInvalid.new(@resource)
      end

      @resource.allow_password_change = false
      @resource.save!

      yield @resource if block_given?

      render json: resource_data, status: :ok
    end

    protected

    def resource_update_method
      if DeviseTokenAuth.check_current_password_before_update == false or @resource.allow_password_change == true
        "update_attributes"
      else
        "update_with_password"
      end
    end

    def render_create_error_missing_email
      render json: {
        success: false,
        errors: [I18n.t("devise_token_auth.passwords.missing_email")]
      }, status: 401
    end

    def render_create_error_missing_redirect_url
      render json: {
        success: false,
        errors: [I18n.t("devise_token_auth.passwords.missing_redirect_url")]
      }, status: 401
    end

    def render_create_error_not_allowed_redirect_url
      render json: {
        status: 'error',
        data:   resource_data,
        errors: [I18n.t("devise_token_auth.passwords.not_allowed_redirect_url", redirect_url: @redirect_url)]
      }, status: 422
    end

    def render_create_success
      render json: {
        success: true,
        message: I18n.t("devise_token_auth.passwords.sended", email: @email)
      }
    end

    def render_create_error
      render json: {
        success: false,
        errors: @errors,
      }, status: @error_status
    end

    def render_edit_error
      raise ActionController::RoutingError.new('Not Found')
    end

    def render_update_error_unauthorized
      render json: {
        success: false,
        errors: ['Unauthorized']
      }, status: 401
    end

    def render_update_error_password_not_required
      render json: {
        success: false,
        errors: [I18n.t("devise_token_auth.passwords.password_not_required", provider: @resource.provider.humanize)]
      }, status: 422
    end

    def render_update_error_missing_password
      render json: {
        success: false,
        errors: [I18n.t("devise_token_auth.passwords.missing_passwords")]
      }, status: 422
    end

    def render_update_success
      render json: {
        success: true,
        data: resource_data,
        message: I18n.t("devise_token_auth.passwords.successfully_updated")
      }
    end

    def render_update_error
      return render json: {
        success: false,
        errors: resource_errors
      }, status: 422
    end

    private

    def resource_params
      params.permit(:email, :password, :password_confirmation, :current_password, :reset_password_token, :redirect_url, :config)
    end

    def password_resource_params
      params.permit(*params_for_resource(:account_update))
    end
  end
end
