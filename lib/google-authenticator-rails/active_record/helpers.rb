module GoogleAuthenticatorRails # :nodoc:
  mattr_accessor :secret_encryptor

  class GoogleQR
    attr_accessor :data, :size, :use_https, :encoding, :error_correction, :margin, :html_options

    def initialize(opts={})
      options = {
        :size => "100x100",
        :use_https => true
      }.merge!(opts)

      options.each {|key,value| self.send("#{key}=", value) }
    end

    def to_s
      if self.data
        params = ["chl=#{escape_string(self.data)}"]
        params << "chs=#{self.size}"
        params << "choe=#{self.encoding}" if self.encoding
        params << error_correction_params if error_correction_param?
        base_url + params.join("&")
      else
        raise "Attribute @data is required for GoogleQR code"
      end
    end

    def render
      if self.size
        height, width = self.size.split('x')
        dimensions = " height='#{height}' width='#{width}' "
      else
        dimensions = nil
      end

      if self.html_options
        html_options = ""

        self.html_options.each do |k, v|
          if k.to_s.length > 0 && v.to_s.length > 0
            html_options += k.to_s + "='" + v.to_s + "' "
          end
        end
      else
        html_options = nil
      end

      "<img src='#{self.to_s}'#{dimensions}#{html_options}/>"
    end

    private
    def base_url
      "http#{self.use_https ? 's' : ''}://chart.googleapis.com/chart?cht=qr&"
    end

    def error_correction_param?
      self.error_correction || self.margin
    end

    def error_correction_params
      if !self.error_correction && self.margin
        param = "L|#{self.margin}"
      elsif self.error_correction && !self.margin
        param = self.error_correction
      else
        param = "#{self.error_correction}|#{self.margin}"
      end

      "chld=#{escape_string(param)}"
    end

    def escape_string(string)
      URI::DEFAULT_PARSER.escape(string, Regexp.new("[^#{URI::PATTERN::UNRESERVED}]"))
    end

  end
  
  module ActiveRecord  # :nodoc:
    module Helpers
      
      # Returns and memoizes the plain text google secret for this instance, irrespective of the
      # name of the google secret storage column and whether secret encryption is enabled for this model.
      #
      def google_secret_value
        if @google_secret_value_cached
          @google_secret_value
        else
          @google_secret_value_cached = true
          secret_in_db = google_secret_column_value
          @google_secret_value = secret_in_db.present? && self.class.google_secrets_encrypted ? google_secret_encryptor.decrypt_and_verify(secret_in_db) : secret_in_db
        end
      end
      
      def set_google_secret
        change_google_secret_to!(GoogleAuthenticatorRails::generate_secret)
      end

      # Sets and saves a nil google secret value for this instance.
      #
      def clear_google_secret!
        change_google_secret_to!(nil)
      end

      def google_authentic?(code)
        GoogleAuthenticatorRails.valid?(code, google_secret_value, self.class.google_drift)
      end

      def google_qr_uri(size = nil)
        GoogleAuthenticatorRails::GoogleQR.new(:data => ROTP::TOTP.new(google_secret_value, :issuer => google_issuer).provisioning_uri(google_label), :size => size || self.class.google_qr_size).to_s
      end

      def google_qr_to_base64(size = 200)
        "data:image/png;base64,#{Base64.strict_encode64(RQRCode::QRCode.new(ROTP::TOTP.new(google_secret_value, :issuer => google_issuer).provisioning_uri(google_label).to_s).as_png(size: size).to_s)}"
      end

      def google_label
        method = self.class.google_label_method
        case method
          when Proc
            method.call(self)
          when Symbol, String
            self.__send__(method)
          else
            raise NoMethodError.new("the method used to generate the google_label was never defined")
        end
      end

      def google_token_value
        self.__send__(self.class.google_lookup_token)
      end
      
      def encrypt_google_secret!
        change_google_secret_to!(google_secret_column_value)
      end

      private
      def default_google_label_method
        self.__send__(self.class.google_label_column)
      end
      
      def google_secret_column_value
        self.__send__(self.class.google_secret_column)
      end

      def change_google_secret_to!(secret, encrypt = self.class.google_secrets_encrypted)
        @google_secret_value = secret
        self.__send__("#{self.class.google_secret_column}=", secret.present? && encrypt ? google_secret_encryptor.encrypt_and_sign(secret) : secret)
        @google_secret_value_cached = true
        save!
      end

      def google_issuer
        issuer = self.class.google_issuer
        issuer.is_a?(Proc) ? issuer.call(self) : issuer
      end
      
      def google_secret_encryptor
        GoogleAuthenticatorRails.secret_encryptor ||= GoogleAuthenticatorRails::ActiveRecord::Helpers.get_google_secret_encryptor
      end
      
      def self.get_google_secret_encryptor
        ActiveSupport::MessageEncryptor.new(Rails.application.key_generator.generate_key('Google-secret encryption key', 32))
      end
    end
  end
end
