use std::sync::Arc;

use lazy_static::lazy_static;
use openssl::pkey::Private;
use openssl::rsa::Rsa;

lazy_static! {
    pub static ref RSA1024A: Arc<Rsa<Private>> =
        Arc::new(Rsa::generate(1024).unwrap());
}
