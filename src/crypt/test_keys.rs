use lazy_static::lazy_static;
use openssl::pkey::Private;
use openssl::rsa::Rsa;

lazy_static! {
    pub static ref RSA1024A: Rsa<Private> = Rsa::generate(1024).unwrap();
}
