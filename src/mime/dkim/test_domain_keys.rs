//-
// Copyright (c) 2023, Jason Lingle
//
// This file is part of Crymap.
//
// Crymap is free software: you can  redistribute it and/or modify it under the
// terms of  the GNU General Public  License as published by  the Free Software
// Foundation, either version  3 of the License, or (at  your option) any later
// version.
//
// Crymap is distributed  in the hope that  it will be useful,  but WITHOUT ANY
// WARRANTY; without  even the implied  warranty of MERCHANTABILITY  or FITNESS
// FOR  A PARTICULAR  PURPOSE.  See the  GNU General  Public  License for  more
// details.
//
// You should have received a copy of the GNU General Public License along with
// Crymap. If not, see <http://www.gnu.org/licenses/>.

/// selector1._domainkey.lin.gl, 2023-12-27
pub static SELECTOR1_LIN_GL: &str =
    "v=DKIM1;p=MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxCRVe\
     M0ctOIvf0NRKs2bcYE3gXjfE9G0s+IY1Iw8cE/XAhisgUraQg5Vzv0d4La+\
     SgQIJEm5XtkTeHFUgWIJM7ZXCI+WOi33+BRn9lwNe9TvoX+zYMCvTLFkEUF\
     /tXihfg/8VcKMC1pc2Ik9bMh020XQUpPJkA/tduYJpq762n1gML0XhxaXHW\
     41Qzkxh2TlATzbBv4V0Lcm4/JXFS9psUB8Sm6TB8N5G5g1zpCQbsA9jFyt3\
     G8VkzUJ4gFJpAqE9czME7BPtVEKHDOSVqA+sztfrUsVjxHoqRXEQR6nj99/\
     uIPprEvjdJ1PyZQKaj9mWqnX7XZor0nGl1tNW+rmfKgIhSh+cRvt2hRbtTF\
     nXL+q6efqK+CwfN5j8pyLkox+S7WITdGrTTXoqPiPSDkjfaJhNi9Uhd/Mbk\
     xF854vDeAm8ZYIIsjwt1p+XIscDP8X7niUOrRuWcpElX+CRtqc2qi2atqAJ\
     hMySZQbh8NW8XVI+EPDYbWA5/JFA5lrf16TuCoyN5uwfaiYTBzTXxlQHWUm\
     sZN/tXkpbO6fHAmc7bvBZfKGMYpmDvKhNZMhmeQjDLkOaSb47AEQf7+weMi\
     qsZEIUhKoQf0En6KNhVWBjezH8022dy7GkxP3Hek+ESxvbwSJHH5mby+TGS\
     U6a+mRausK4Ji72JhXH4PvnEvtimECAwEAAQ==;s=email;t=s";

/// s2048._domainkey.yahoo.com, 2023-12-27
pub static S2048_YAHOO_COM: &str =
    "k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuoWufg\
     bWw58MczUGbMv176RaxdZGOMkQmn8OOJ/HGoQ6dalSMWiLaj8IMcHC1cubJ\
     x2gziAPQHVPtFYayyLA4ayJUSNk10/uqfByiU8qiPCE4JSFrpxflhMIKV4b\
     t+g1uHw7wLzguCf4YAoR6XxUKRsAoHuoF7M+v6bMZ/X1G+viWHkBl4UfgJQ\
     6O8F1ckKKoZ5KqUkJH5pDaqbgs+F3PpyiAUQfB6EEzOA1KMPRWJGpzgPtKo\
     ukDcQuKUw9GAul7kSIyEcizqrbaUKNLGAmz0elkqRnzIsVpz6jdT1/YV5Ri\
     6YUOQ5sN5bqNzZ8TxoQlkbVRy6eKOjUnoSSTmSAhwIDAQAB;";

/// yg4mwqurec7fkhzutopddd3ytuaqrvuz._domainkey.amazon.com, 2023-12-27
pub static YG4_AMAZON_COM: &str =
    "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5bK96ORNNFosbAaVNZ\
     U/gVzhANHyd00o1O7qbEeMNLKPNpS8/TYwdlrVnQ7JtJHjIR9EPj61jgtS6\
     04XpAltDMYvic2I40AaKgSfr4dDlRcALRtlVqmG7U5MdLiMyabxXPl2s/oq\
     kevALySg0sr/defHC+qAhmdot9Ii/ZQ3YcQIDAQAB";

/// hsbnp7p3ensaochzwyq5wwmceodymuwv._domainkey.amazonses.com, 2023-12-28
pub static HSG_AMAZONSES_COM: &str =
    "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvt2uMyV5G8KQJlwmiu\
     54Z6crNCpYlzuj1DVcajAd7PvEEUXxiT1lejc+D5ELrKnB4jpNN+4xmkvJQ\
     0sO0RySXJNbbNKUFYav+A4HgLPlqcNSSP5YYaejvsfBQYmvpiMA8+M+NAjy\
     yMvm+5/23YFF8st4gJD3C19VGjlAJf/AxgQIDAQAB";

/// 20230601._domainkey.gmail.com, 2023-12-27
pub static K20230601_GMAIL_COM: &str =
    "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA\
     QEAntvSKT1hkqhKe0xcaZ0x+QbouDsJuBfby/S82jxsoC/SodmfmVs2D1KA\
     H3mi1AqdMdU12h2VfETeOJkgGYq5ljd996AJ7ud2SyOLQmlhaNHH7Lx+Mda\
     b8/zDN1SdxPARDgcM7AsRECHwQ15R20FaKUABGu4NTbR2fDKnYwiq5jQyBk\
     LWP+LgGOgfUF4T4HZb2PY2bQtEP6QeqOtcW4rrsH24L7XhD+HSZb1hsitrE\
     0VPbhJzxDwI4JF815XMnSVjZgYUXP8CxI1Y0FONlqtQYgsorZ9apoW1KPQe\
     8brSSlRsi9sXB/tu56LmG7tEDNmrZ5XUwQYUUADBOu7t1niwXwIDAQAB";
