pub struct JwtDecoderProvider;

impl TokenEncoderProvider for JwtDecoderProvider {
    fn provide(&self, token: String) -> Option<String> {
        // let mut validation = Validation::new(Algorithm::HS256);
        // validation.validate_exp = true;
        // validation.required_spec_claims = HashSet::from(["exp".to_owned()]);
        //
        // let token_data = decode::<Claims>(token, &self.decoding_key, &validation).map_err(|_| None);
        //
        // Some(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_jwt() {
        // Given
        let jwt_encoder = JwtDecoderProvider;

        // When
        let token = jwt_encoder.provide("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJRd2VydHkxMjMiLCJleHAiOjE3NjYwNzk3MzgsImlhdCI6MTc2NjA3ODgzOH0.OQaBFmEhmrHc7IVtaEXz5ozEVamTKCD_1Qe_YZd0um0".to_owned()).unwrap();

        // Then
        assert_ne!(token, "!Qwerty123".to_owned());
    }
}
