from rbqwrapper import RbqWrapper, main


def test_init():
    RbqWrapper()

def test_null():
    main([])
