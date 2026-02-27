from validatedata.validatedata import validate_data
from validatedata.messages import error_messages
from .base import BaseTest


class TestNewTypes(BaseTest):

    # --- URL ---

    def test_url_valid(self):
        self.assertTrue(validate_data(['https://example.com'], self.all_url_rules[0]).ok)
        self.assertTrue(validate_data(['http://example.com/path?q=1'], self.all_url_rules[0]).ok)
        self.assertTrue(validate_data(['ftp://files.example.org'], self.all_url_rules[0]).ok)

    def test_url_invalid(self):
        result = validate_data(['not-a-url'], self.all_url_rules[0])
        self.assertFalse(result.ok)
        self.assertIn(error_messages['invalid_url'], result.errors[0])

    def test_url_invalid_no_scheme(self):
        self.assertFalse(validate_data(['example.com'], self.all_url_rules[0]).ok)

    def test_url_with_startswith_rule(self):
        # rule requires startswith 'https'
        self.assertTrue(validate_data(['https://secure.example.com'], self.all_url_rules[1]).ok)
        self.assertFalse(validate_data(['http://insecure.example.com'], self.all_url_rules[1]).ok)

    # --- IP address ---

    def test_ip_valid_v4(self):
        self.assertTrue(validate_data(['192.168.1.1'], self.all_ip_rules[0]).ok)
        self.assertTrue(validate_data(['0.0.0.0'], self.all_ip_rules[0]).ok)
        self.assertTrue(validate_data(['255.255.255.255'], self.all_ip_rules[0]).ok)

    def test_ip_valid_v6(self):
        self.assertTrue(validate_data(['::1'], self.all_ip_rules[0]).ok)
        self.assertTrue(validate_data(['2001:db8::1'], self.all_ip_rules[0]).ok)

    def test_ip_invalid(self):
        result = validate_data(['999.999.1.1'], self.all_ip_rules[0])
        self.assertFalse(result.ok)
        self.assertIn(error_messages['invalid_ip'], result.errors[0])

    def test_ip_invalid_non_ip_string(self):
        self.assertFalse(validate_data(['not-an-ip'], self.all_ip_rules[0]).ok)

    # --- UUID ---

    def test_uuid_valid(self):
        self.assertTrue(
            validate_data(['550e8400-e29b-41d4-a716-446655440000'], self.all_uuid_rules[0]).ok
        )
        # uppercase should also be accepted
        self.assertTrue(
            validate_data(['550E8400-E29B-41D4-A716-446655440000'], self.all_uuid_rules[0]).ok
        )

    def test_uuid_invalid(self):
        result = validate_data(['not-a-uuid'], self.all_uuid_rules[0])
        self.assertFalse(result.ok)
        self.assertIn(error_messages['invalid_uuid'], result.errors[0])

    def test_uuid_invalid_too_short(self):
        self.assertFalse(validate_data(['550e8400-e29b-41d4'], self.all_uuid_rules[0]).ok)

    # --- Slug ---

    def test_slug_valid(self):
        self.assertTrue(validate_data(['hello-world'], self.all_slug_rules[0]).ok)
        self.assertTrue(validate_data(['simple'], self.all_slug_rules[0]).ok)
        self.assertTrue(validate_data(['a1b2-c3'], self.all_slug_rules[0]).ok)

    def test_slug_invalid_uppercase(self):
        result = validate_data(['Hello-World'], self.all_slug_rules[0])
        self.assertFalse(result.ok)
        self.assertIn(error_messages['invalid_slug'], result.errors[0])

    def test_slug_invalid_spaces(self):
        self.assertFalse(validate_data(['hello world'], self.all_slug_rules[0]).ok)

    def test_slug_invalid_leading_hyphen(self):
        self.assertFalse(validate_data(['-leading'], self.all_slug_rules[0]).ok)

    def test_slug_with_length_rule(self):
        self.assertTrue(validate_data(['hello'], self.all_slug_rules[1]).ok)   # exactly 5
        self.assertFalse(validate_data(['hi'], self.all_slug_rules[1]).ok)     # too short

    # --- Semantic version ---

    def test_semver_valid(self):
        self.assertTrue(validate_data(['1.0.0'], self.all_semver_rules[0]).ok)
        self.assertTrue(validate_data(['0.1.0'], self.all_semver_rules[0]).ok)
        self.assertTrue(validate_data(['10.20.30'], self.all_semver_rules[0]).ok)

    def test_semver_valid_prerelease(self):
        self.assertTrue(validate_data(['1.0.0-alpha'], self.all_semver_rules[0]).ok)
        self.assertTrue(validate_data(['1.0.0-alpha.1'], self.all_semver_rules[0]).ok)
        self.assertTrue(validate_data(['1.0.0-0.3.7'], self.all_semver_rules[0]).ok)

    def test_semver_valid_build_metadata(self):
        self.assertTrue(validate_data(['1.0.0+build.1'], self.all_semver_rules[0]).ok)
        self.assertTrue(validate_data(['1.0.0-beta+exp.sha.5114f85'], self.all_semver_rules[0]).ok)

    def test_semver_invalid(self):
        result = validate_data(['1.2'], self.all_semver_rules[0])
        self.assertFalse(result.ok)
        self.assertIn(error_messages['invalid_semver'], result.errors[0])

    def test_semver_invalid_leading_zero(self):
        self.assertFalse(validate_data(['01.2.3'], self.all_semver_rules[0]).ok)

    def test_semver_invalid_non_numeric(self):
        self.assertFalse(validate_data(['one.two.three'], self.all_semver_rules[0]).ok)

    # --- Color ---

    def test_color_hex_valid(self):
        self.assertTrue(validate_data(['#ff0000'], self.all_color_rules[1]).ok)
        self.assertTrue(validate_data(['#FFF'], self.all_color_rules[1]).ok)
        self.assertTrue(validate_data(['#aabbcc'], self.all_color_rules[1]).ok)

    def test_color_hex_invalid(self):
        result = validate_data(['ff0000'], self.all_color_rules[1])  # missing #
        self.assertFalse(result.ok)
        self.assertIn(error_messages['invalid_color'], result.errors[0])

    def test_color_rgb_valid(self):
        self.assertTrue(validate_data(['rgb(255, 0, 0)'], self.all_color_rules[2]).ok)
        self.assertTrue(validate_data(['rgb(0,0,0)'], self.all_color_rules[2]).ok)

    def test_color_rgb_invalid(self):
        self.assertFalse(validate_data(['rgb(300, 0, 0)'], self.all_color_rules[2]).ok)

    def test_color_hsl_valid(self):
        self.assertTrue(validate_data(['hsl(0, 100%, 50%)'], self.all_color_rules[3]).ok)
        self.assertTrue(validate_data(['hsl(360, 0%, 0%)'], self.all_color_rules[3]).ok)

    def test_color_hsl_invalid(self):
        self.assertFalse(validate_data(['hsl(400, 100%, 50%)'], self.all_color_rules[3]).ok)

    def test_color_named_valid(self):
        self.assertTrue(validate_data(['red'], self.all_color_rules[4]).ok)
        self.assertTrue(validate_data(['cornflowerblue'], self.all_color_rules[4]).ok)

    def test_color_named_invalid(self):
        result = validate_data(['notacolor'], self.all_color_rules[4])
        self.assertFalse(result.ok)
        self.assertIn(error_messages['invalid_color'], result.errors[0])

    def test_color_any_format(self):
        # rule[0] has no format restriction — all valid formats accepted
        self.assertTrue(validate_data(['#abc'], self.all_color_rules[0]).ok)
        self.assertTrue(validate_data(['rgb(1,2,3)'], self.all_color_rules[0]).ok)
        self.assertTrue(validate_data(['blue'], self.all_color_rules[0]).ok)
        self.assertFalse(validate_data(['notacolor'], self.all_color_rules[0]).ok)

    # --- Phone ---

    def test_phone_e164_valid(self):
        self.assertTrue(validate_data(['+12025550123'], self.all_phone_rules[0]).ok)
        self.assertTrue(validate_data(['+441234567890'], self.all_phone_rules[0]).ok)

    def test_phone_e164_invalid(self):
        result = validate_data(['5550123'], self.all_phone_rules[0])
        self.assertFalse(result.ok)
        self.assertIn(error_messages['invalid_phone'], result.errors[0])

    def test_phone_invalid_no_plus(self):
        self.assertFalse(validate_data(['12025550123'], self.all_phone_rules[0]).ok)

    def test_phone_invalid_too_short(self):
        self.assertFalse(validate_data(['+1234'], self.all_phone_rules[0]).ok)

    # --- Prime ---

    def test_prime_valid(self):
        for n in [2, 3, 5, 7, 11, 13, 97]:
            with self.subTest(n=n):
                self.assertTrue(validate_data([n], self.all_prime_rules[0]).ok)

    def test_prime_invalid_composites(self):
        for n in [4, 6, 9, 15, 100]:
            with self.subTest(n=n):
                result = validate_data([n], self.all_prime_rules[0])
                self.assertFalse(result.ok)
                self.assertIn(error_messages['not_prime'], result.errors[0])

    def test_prime_invalid_edge_cases(self):
        # 0 and 1 are not prime by definition
        self.assertFalse(validate_data([0], self.all_prime_rules[0]).ok)
        self.assertFalse(validate_data([1], self.all_prime_rules[0]).ok)

    def test_prime_invalid_negative(self):
        self.assertFalse(validate_data([-7], self.all_prime_rules[0]).ok)

    def test_prime_accepts_string_representation(self):
        # validator should coerce '7' to int and accept it
        self.assertTrue(validate_data(['7'], self.all_prime_rules[0]).ok)
