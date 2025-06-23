"""City of Austin Utilities."""

from typing import Optional
from urllib.parse import parse_qs, urlparse

import base64
import re
import aiohttp
from yarl import URL

from ..const import USER_AGENT
from ..exceptions import InvalidAuth, CannotConnect
from .base import UtilityBase
from .helpers import get_form_action_url_and_hidden_inputs


class COAUtilities(UtilityBase):
    """City of Austin Utilities."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "City of Austin Utilities"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "coa"

    @staticmethod
    def timezone() -> str:
        """Return the timezone.

        Should match the siteTimeZoneId of the API responses.
        """
        return "America/Chicago"

    @staticmethod
    def is_dss() -> bool:
        """Check if Utility using DSS version of the portal."""
        return True

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        optional_mfa_secret: Optional[str],
    ) -> Optional[str]:
        """Login to the utility website."""
        # Get cookies
        print("COAUtilities: Getting initial cookies from coautilities.com home...")
        await session.get(
            "https://coautilities.com/wps/wcm/connect/occ/coa/home",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        )
        print("COAUtilities: Initial cookies obtained.")

        # Auth using username and password on coautilities
        url = (
            "https://coautilities.com/pkmslogin.form?/isam/sps/OPowerIDP_DSS/saml20/logininitial?"
            "RequestBinding=HTTPPost&"
            "NameIdFormat=email&"
            "PartnerId=opower-coa-dss-webUser&"
            "Target=https://dss-coa.opower.com"
        )
        print(f"COAUtilities: Posting credentials to COA login form: {url}")
        async with session.post(
            url,
            headers={"User-Agent": USER_AGENT},
            data={
                "username": username,
                "password": password,
                "login-form-type": "pwd",
            },
            raise_for_status=True,
        ) as response:
            await response.text()  # Consume response body
            if "PD-S-SESSION-ID-PCOAUT" not in session.cookie_jar.filter_cookies(URL("https://coautilities.com")):
                print("COAUtilities: Login to coautilities.com failed (PD-S-SESSION-ID-PCOAUT cookie not found).")
                raise InvalidAuth("Username/Password are invalid on coautilities.com")
            print("COAUtilities: Successfully logged into coautilities.com.")

        # Getting SAML Request from opower
        opower_sso_init_url = (
            "https://sso.opower.com/sp/startSSO.ping?"
            "PartnerIdpId=https://coautilities.com/isam/sps/OPowerIDP_DSS/saml20&"
            "TargetResource=https%3A%2F%2Fdss-coa.opower.com%2Fwebcenter%2Fedge%2Fapis%2Fidentity-management-v1%2Fcws"
            "%2Fv1%2Fauth%2Fcoa%2Fsaml%2Flogin%2Fcallback%3FsuccessUrl%3Dhttps%253A%252F%252Fdss-coa.opower.com%252Fdss"
            "%252Flogin-success%253Ftoken%253D%2525s%2526nextPathname%253DL2Rzcy8%253D%26failureUrl%3Dhttps%253A%252F"
            "%252Fdss-coa.opower.com%252Fdss%252Flogin-error%253Freason%253D%2525s"
        )
        print(f"COAUtilities: Initiating SAML SSO with Opower: {opower_sso_init_url}")
        async with session.post(opower_sso_init_url, raise_for_status=True) as response:
            html = await response.text()
            action_url, hidden_inputs = get_form_action_url_and_hidden_inputs(html)
            print(f"COAUtilities: Opower sso.opower.com responded. Next action_url: {action_url}")

            # ---- START ADDED SAMLRequest DEBUG PRINTING ----
            if "SAMLRequest" in hidden_inputs:
                saml_request_b64 = hidden_inputs["SAMLRequest"]
                print("\nCOAUtilities: --- Raw SAMLRequest (Base64 Encoded) ---")
                print(saml_request_b64)
                print("COAUtilities: --- End Raw SAMLRequest ---\n")
                try:
                    decoded_saml_request_bytes = base64.b64decode(saml_request_b64)
                    try:
                        decoded_saml_request_xml = decoded_saml_request_bytes.decode("utf-8")
                        print("\nCOAUtilities: --- Decoded SAMLRequest (XML - first 1000 chars) ---")
                        print(decoded_saml_request_xml[:1000])  # Print more chars if needed
                        print("COAUtilities: --- End Decoded SAMLRequest ---\n")
                    except UnicodeDecodeError:
                        print(
                            f"COAUtilities: SAMLRequest decoded from Base64 but is not valid UTF-8. It might be compressed. Length: {len(decoded_saml_request_bytes)} bytes\n"
                        )
                except Exception as e:
                    print(f"COAUtilities: Could not decode or process SAMLRequest: {e}\n")
            else:
                print(
                    f"COAUtilities: SAMLRequest NOT found in hidden_inputs from sso.opower.com. Keys found: {list(hidden_inputs.keys())}\n"
                )

            # This assertion will fail if SAMLRequest or RelayState is missing, or if other keys are present.
            if not ("RelayState" in hidden_inputs and "SAMLRequest" in hidden_inputs):
                print(
                    f"COAUtilities: ERROR - Expected 'RelayState' and 'SAMLRequest' not found in hidden inputs. Found: {list(hidden_inputs.keys())}"
                )
                # You might want to raise an error here or handle it,
                # but for debugging the SAMLRequest, the prints above are key.

            assert set(hidden_inputs.keys()) == {"RelayState", "SAMLRequest"}
            print(f"COAUtilities: Hidden inputs from sso.opower.com (keys): {list(hidden_inputs.keys())}")

        # Getting SAML Response from coautilities (THIS IS WHERE THE ERROR OCCURS)
        print(f"COAUtilities: Posting SAMLRequest to COA IdP at: {action_url}")  # action_url is from the previous step
        headers = {
            "Referer": "https://sso.opower.com/",  # The previous page was sso.opower.com
            "User-Agent": USER_AGENT,
        }
        async with session.post(
            action_url,  # This should be COA's IdP endpoint, e.g., https://coautilities.com/isam/sps/OPowerIDP_DSS/saml20/login
            headers=headers,
            data=hidden_inputs,  # This contains the SAMLRequest from Opower
            raise_for_status=False,  # Changed to False to inspect error response
        ) as response:
            html_response_from_coa_idp = await response.text()
            print(f"COAUtilities: Response status from COA IdP after posting SAMLRequest: {response.status}")
            print("\nCOAUtilities: --- HTML response from COA IdP ---")
            print(f"COAUtilities: Fetched from URL: {response.real_url}")
            print(html_response_from_coa_idp)
            print("COAUtilities: --- End HTML response from COA IdP ---\n")

            if response.status != 200 or "FBTSML224E Cannot find partner configuration" in html_response_from_coa_idp:
                match = re.search(r"provider\s+([^\s.]+)\.", html_response_from_coa_idp)
                provider_name = match.group(1) if match else "unknown"
                error_detail = f"COA IdP SAML error: Cannot find partner configuration for provider '{provider_name}'."
                print(f"COAUtilities: ERROR - {error_detail}")
                raise CannotConnect(error_detail + " This is likely a server-side SAML federation misconfiguration.")

            # If we didn't raise an error, proceed to parse the (expected) SAMLResponse form
            action_url, hidden_inputs = get_form_action_url_and_hidden_inputs(html_response_from_coa_idp)
            print(f"COAUtilities: Parsed from COA IdP response. Next action_url: {action_url}")
            print(f"COAUtilities: Hidden inputs from COA IdP response (keys): {list(hidden_inputs.keys())}")
            assert set(hidden_inputs.keys()) == {"RelayState", "SAMLResponse"}  # This is the original failing assertion

        # Getting Open Token from opower
        print(f"COAUtilities: Posting SAMLResponse to Opower ACS: {action_url}")
        async with session.post(
            action_url,  # This is Opower's ACS URL
            headers={"User-Agent": USER_AGENT},
            data=hidden_inputs,  # This should contain SAMLResponse and RelayState
            raise_for_status=True,
        ) as response:
            html = await response.text()
            action_url, hidden_inputs = get_form_action_url_and_hidden_inputs(html)
            print(f"COAUtilities: Opower ACS responded. Next action_url: {action_url}")
            print(f"COAUtilities: Hidden inputs from Opower ACS (keys): {list(hidden_inputs.keys())}")
            assert set(hidden_inputs.keys()) == {"opentoken"}

        session.cookie_jar.update_cookies({"dssPortalCW": "1"})
        print("COAUtilities: dssPortalCW cookie updated.")

        # Getting success token
        print(f"COAUtilities: Posting opentoken to Opower: {action_url}")
        async with session.post(
            action_url,
            headers={"User-Agent": USER_AGENT},
            data=hidden_inputs,  # This contains the opentoken
            allow_redirects=False,  # Important: we need to capture the redirect Location header
            raise_for_status=True,  # Expecting a 302 redirect, so this might actually error out if not handled correctly.
            # aiohttp's raise_for_status usually doesn't trigger on 3xx unless allow_redirects=False and no Location.
            # However, if it's a 302, we need to ensure we get the Location.
        ) as response:
            # We expect a redirect (302) here.
            # The original code implicitly relied on raise_for_status=True not failing on 302,
            # OR it might have been expecting the next request to handle the actual redirect.
            # Let's be explicit.
            print(f"COAUtilities: Opower opentoken POST response status: {response.status}")
            if response.status not in (301, 302, 303, 307, 308):  # Common redirect statuses
                # If not a redirect, something is wrong, or the flow changed.
                html_content_after_opentoken = await response.text()
                print(
                    "COAUtilities: ERROR - Expected redirect after posting opentoken, but got status "
                    f"{response.status}. Response content:\n{html_content_after_opentoken}"
                )
                raise CannotConnect(f"Expected redirect after opentoken POST, got {response.status}")

            location_header = response.headers.get("Location")
            if not location_header:
                print("COAUtilities: ERROR - Redirect expected after opentoken POST, but no Location header found.")
                raise CannotConnect("No Location header in redirect after opentoken POST.")

            print(f"COAUtilities: Redirect Location after opentoken POST: {location_header}")
            parsed_url = urlparse(location_header)
            parsed_query = parse_qs(parsed_url.query)
            if "token" not in parsed_query:
                print(f"COAUtilities: ERROR - 'token' not found in redirect query parameters. Found: {parsed_query}")
                raise CannotConnect("'token' not found in redirect after opentoken POST.")

            token = parsed_query["token"][0]
            print(f"COAUtilities: Extracted success token: {token[:20]}...")  # Print first 20 chars

        # Finally exchange this token to Auth token
        confirm_url = (
            "https://dss-coa.opower.com" "/webcenter/edge/apis/identity-management-v1/cws/v1/auth/coa/saml/ott/confirm"
        )
        print(f"COAUtilities: Confirming OTT (success token) with Opower: {confirm_url}")
        async with session.post(
            confirm_url,
            headers={"User-Agent": USER_AGENT},
            data={"token": token},
            raise_for_status=True,
        ) as response:
            content = await response.json()
            session_token = content.get("sessionToken")
            if not session_token:
                print(f"COAUtilities: ERROR - 'sessionToken' not found in OTT confirmation response. Got: {content}")
                raise CannotConnect("'sessionToken' not found after OTT confirmation.")
            print(f"COAUtilities: Successfully obtained sessionToken: {session_token[:20]}...")
            return str(session_token)
