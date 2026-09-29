from leakscan.entropy import is_high_entropy, shannon_entropy


def test_repeated_chars_have_zero_entropy():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_random_looking_token_is_flagged():
    assert is_high_entropy("9fK2xQ7LmB4vTz8RcW1nYd6HsJ3aPe0U")


def test_placeholder_is_not_flagged():
    assert not is_high_entropy("YOUR_API_KEY_HERE_PLEASE")