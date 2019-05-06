from simple_ad.simple_ad import ActiveDirectory
import pytest


@pytest.fixture()
def test_setup():
    print("Setting Up Test:")
    global ad
    ad = ActiveDirectory()
    yield
    print("Tearing Down Test")
    ad = None
    print("Test Complete")


def test_get_user_by_samaccountname(test_setup):
    u = ad.get_user_by_samaccountname('moocs')
    assert u is not None


def test_get_user_by_cn(test_setup):
    u = ad.get_user_by_cn('Marcus Robb')
    assert u is not None




