-- tenant private key: MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAPXh6Jua31S030hiyvZ8PzZiY3KvsrCex9ODD8t3uTCxQ5UpnhOVFwLoI/M93uxe1tKZdgekvjVQiJ2dK6rrVuCMZe6gj3BYJxu0bzZkD3vBFg10lAzJghH0u5caePVEAWpi0rHVQkOMNy+IAd4SDXMQGBD0BrxHZ3Ok2PwtlEbhAgMBAAECgYEA17L6b6cJTDHvvnyMOHb+rSLawv1G8JIaEn7jGEdK+mBHPU9pERy1NyOWhgg8y3bXVaCyXjozcmnXrwz2Bda2OkY50ay/urNgd3b0ruyVw0M068gVsB6CPf5HqG34NIkqR8ubD+aBofscLoWuyPfNMthDYTojzonEl33oA26lDwECQQD9WMJL/NHJmSQ80JDGLBOZ3xvbEXDd1h1LEsoZQvE9LKUEHOWnq8NM4JohmDR48Jkz60BYlpnSpzOfV2049pSZAkEA+HUjLookySzCKTbaVQmczHdDr9a/hjVwHBItbVuM72EMKTXhQnAdn6bDIX7YkoxtHcgRd/07UD3wHAWIg4xpiQJAIUC3L/YdKxLYuMq/VeOPJxErvNNLNzLVYXcz46DvvRHRDvskAZ//4GVSlbo+mOkrkq78ISSTSBz+H5oAEgv7cQJAd0OrXrS7UcJldWk6RuW1WcTKPgcEqsTOCvuCyOLQdTwNnV6awcyVu8ROGK8OANLdshUOpZ1uMmd48cqKLDNjmQJABXU18/LJvZ/wnPoEt0VfjDxBumU9EHD9HsMrfCkL95We9Q1gH6z9hGO7e2rYsNwZnXPzWmjlJiAIQ3MeKHgiyA==
INSERT INTO "PUBLIC"."TENANT"("ID","DESC","NAME","ENCRYPT_AES_KEY","ENCRYPT_ALGORITHM","IS_DYMANIC_SERCET_KEY","PLAT_FORM_DH_PUBLIC_KEY","PLATFORM_DH_PRIVATE_KEY","PLATFORM_EC_PRIVATE_KEY","PLATFORM_EC_PUBLIC_KEY","PLATFORM_RSA_PRIVATE_KEY","PLATFORM_RSA_PUBLIC_KEY","SIGNATURE_AES_KEY","SIGNATURE_ALGORITHM","TENANT_DH_PUBLIC_KEY","TENANT_EC_PUBLIC_KEY","TENANT_RSA_PUBLIC_KEY")VALUES(
'1','测试租户','tenant','ouP5XAY8eH7aOb3ou6hdhA==','AES',false, null,null,null,null,'MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAOlCCdg0q8gumW1T5PizhjEXQC8dONdU7zdhvKB5SI+ubNme+7ouHk+w/8hzlagjF7JLQnu3ylGSc59T1JsUZ+aSB/HYIsuk+ejQq8+1paJgWMUsMx4cG/HOTc2BADsnjnqm3DiwW/dJ7vL+sgvwqK456cWplDzJPwOAbZGIADDJAgMBAAECgYEAmStXQZUctF/9OfBcK//e/39wE0ASIjxQtUJF1e6uekMkkSa30AMWvmfRHrTfskARAHAxIQKIJVaQ/C/VLVyR+HIp830qREyhMfIFfYfsex50MPLxMrdDcOSElp/8GYoJMDOxgr0N/wQfVwMWtsYTpEOZF/KYjb4qjuzTqApOzgECQQD6G/BmpBGcqtNvCiR/9KGBQ0cBG87r1cC/JtmMwMmktk4OzZ6NB54YVruk5BkNq1/fCinmK4XVb/6LHHUGvs1BAkEA7sB+TH1tV9bhul1pJcXUUQK16AZvX7tHJZHa78atQ7N/1wyJDNVSEo7yik4wxY2YK5jyeoRtaTKNNCqyHpkZiQJALb0IRK0Cb4Up72eKbz/8fRghlwlP2P8ZJZvkMwJand2c/sYJlb7r4YWTAT+ZeU96094W9XnGGtdFVIlauWYRQQJALRuVQSJZbEUe9LT9TrOnv36Bm8rLdAzQDlsWQEMLLUVWm+y0YAZVsUfsrxDCyjBMVcBZ36fxe/SfFQIUEQ/f8QJBAPY67aAl+Qgg2o6PTz9rlb5hayBElbd4UlkBfDOsLLNWChTgf5c8Huf6JfKuX4vS6zH8cJntYLGmksGQ14SQGMs=','MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDpQgnYNKvILpltU+T4s4YxF0AvHTjXVO83YbygeUiPrmzZnvu6Lh5PsP/Ic5WoIxeyS0J7t8pRknOfU9SbFGfmkgfx2CLLpPno0KvPtaWiYFjFLDMeHBvxzk3NgQA7J456ptw4sFv3Se7y/rIL8KiuOenFqZQ8yT8DgG2RiAAwyQIDAQAB',null,'RSA',null,null,'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD14eibmt9UtN9IYsr2fD82YmNyr7KwnsfTgw/Ld7kwsUOVKZ4TlRcC6CPzPd7sXtbSmXYHpL41UIidnSuq61bgjGXuoI9wWCcbtG82ZA97wRYNdJQMyYIR9LuXGnj1RAFqYtKx1UJDjDcviAHeEg1zEBgQ9Aa8R2dzpNj8LZRG4QIDAQAB'
);
