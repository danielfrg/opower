import argparse
import asyncio
import logging
from getpass import getpass  # For securely getting password if not provided via args

import aiohttp

# Ensure the opower library is accessible. If running from the project root
# and opower is installed (e.g., `pip install -e .`), this should work.
try:
    from opower import Opower, InvalidAuth, CannotConnect, create_cookie_jar
    from opower.exceptions import ApiException
except ImportError as e:
    print(e)
    print(
        "Error: Could not import the opower library. \n"
        "Please ensure it's installed and your PYTHONPATH is set up correctly, \n"
        "or run this script from the root of the opower project after installing with `pip install -e .`."
    )
    exit(1)


async def main_test_coa_login():
    parser = argparse.ArgumentParser(description="Test City of Austin Utilities login with opower library.")
    parser.add_argument("--username", help="Username for City of Austin Utilities")
    parser.add_argument("--password", help="Password for City of Austin Utilities (will prompt if not provided)")
    parser.add_argument(
        "-v", "--verbose", help="Enable verbose logging. Use -vv for maximum verbosity.", action="count", default=0
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.INFO
    if args.verbose == 1:
        log_level = logging.DEBUG
    elif args.verbose >= 2:
        # Custom level for very verbose output, similar to opower's __main__.py
        # logging.DEBUG is 10. Levels < 10 are more verbose.
        log_level = logging.DEBUG - (args.verbose - 1)
        if log_level < 1:  # Python logging levels must be >= 1
            log_level = 1

    logging.basicConfig(level=log_level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    # If very verbose, set opower library loggers to the same high verbosity
    if args.verbose >= 2:
        logging.getLogger("opower").setLevel(log_level)
        # Specifically target the coautilities module for detailed logs
        logging.getLogger("opower.utilities.coautilities").setLevel(log_level)
        logging.getLogger("opower.opower").setLevel(log_level)  # For Opower class methods
        # Add other opower submodules if their logs become relevant
        # logging.getLogger("opower.utilities.helpers").setLevel(log_level)

    username = args.username or input("Enter City of Austin Utilities Username: ")
    password = args.password or getpass("Enter City of Austin Utilities Password: ")

    utility_name = "City of Austin Utilities"
    # Alternatively, you can use the internal identifier: "coautilities"

    print(f"Using opower library to test login for: {utility_name}")
    print(f"Username: {username}")
    print(f"Logging Level: {logging.getLevelName(log_level)} ({log_level})")
    print("-" * 30)

    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower_client = Opower(
            session=session,
            utility=utility_name,
            username=username,
            password=password,
            # mfa_secret is not applicable for COA as its accepts_mfa() defaults to False
        )

        try:
            print("Attempting to log in...")
            logging.info("Starting opower_client.async_login()")
            await opower_client.async_login()
            logging.info("opower_client.async_login() completed without raising an immediate opower exception.")
            print("\nLogin attempt finished.")
            print("If no specific opower exceptions (InvalidAuth, CannotConnect, ApiException) were raised,")
            print("the login *may* have appeared successful to the Opower class's async_login method.")
            print(
                "However, an underlying assertion or other error might have occurred if the SAML flow was not fully successful."
            )
            print("Check the verbose logs above for details of the HTTP requests and responses,")
            print("and look for any AssertionErrors or other unexpected Python errors.")

            # You could try to fetch accounts to further test the session
            # print("\nAttempting to fetch accounts...")
            # try:
            #     accounts = await opower_client.async_get_accounts()
            #     print(f"Successfully fetched accounts: {accounts}")
            # except Exception as e_acct:
            #     print(f"Error fetching accounts after login: {e_acct}")
            #     logging.error("Error during async_get_accounts", exc_info=True)

        except InvalidAuth as e:
            print(f"\nLOGIN FAILED: Invalid credentials or authentication issue.")
            logging.error("InvalidAuth exception caught", exc_info=True)
        except CannotConnect as e:
            print(f"\nLOGIN FAILED: Could not connect to the service.")
            logging.error("CannotConnect exception caught", exc_info=True)
        except ApiException as e:
            print(f"\nLOGIN FAILED: API communication error.")
            logging.error("ApiException caught", exc_info=True)
            if e.response_text:
                print("\n--- API Response Text that caused ApiException ---")
                print(e.response_text)
                print("--------------------------------------------------")
        except AssertionError as e:
            print(f"\nLOGIN FAILED: An assertion failed during the login process.")
            print(
                "This often happens if an intermediate page did not contain expected elements (e.g., a form or specific hidden fields)."
            )
            print("The error message from the utility might be present in the logs above (look for HTML content).")
            logging.error("AssertionError caught", exc_info=True)
        except Exception as e:
            print(f"\nLOGIN FAILED: An unexpected error occurred.")
            logging.error("Unexpected exception caught", exc_info=True)
        finally:
            print("-" * 30)
            print("Test script finished.")


if __name__ == "__main__":
    asyncio.run(main_test_coa_login())
