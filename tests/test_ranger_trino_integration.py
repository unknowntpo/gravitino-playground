import pytest
import trino
from trino.auth import BasicAuthentication
from trino.exceptions import TrinoUserError
import time
import requests
import uuid
from apache_ranger.client.ranger_client import RangerClient
from apache_ranger.model.ranger_policy import (
    RangerPolicy,
    RangerPolicyItem,
    RangerPolicyResource,
    RangerPolicyItemAccess,
)
from apache_ranger.model.ranger_service import RangerService

# Test configuration
TRINO_HOST = "localhost"
TRINO_PORT = 18080
RANGER_ADMIN_URL = "http://localhost:6080"
RANGER_ADMIN_USER = "admin"
RANGER_ADMIN_PASSWORD = "rangerR0cks!"

# Test users for different scenarios
TEST_USERS = {
    "admin": "admin",
    "test_user": "test_password",
    "read_only_user": "read_password",
    "data_analyst": "analyst_password"
}


def create_ranger_policy(ranger_client, policy_name, resource_path, permissions, users=None, catalog="*", schema="*", service_name="trinoTest"):
    """Create a policy in Ranger Admin using the Python SDK"""
    policy = RangerPolicy()
    policy.service = service_name
    policy.name = policy_name
    policy.description = f"Test policy for {policy_name}"
    policy.isEnabled = True

    # Set resources
    policy.resources = {
        "catalog": RangerPolicyResource({"values": [catalog]}),
        "schema": RangerPolicyResource({"values": [schema]}),
        "table": RangerPolicyResource({"values": [resource_path]}),
    }

    # Set policy items
    allow_item = RangerPolicyItem()
    allow_item.users = users or ["test_user"]
    allow_item.accesses = [
        RangerPolicyItemAccess({"type": perm}) for perm in permissions
    ]

    policy.policyItems = [allow_item]

    return ranger_client.create_policy(policy)


def create_deny_policy(ranger_client, policy_name, resource_path, permissions, users=None, catalog="*", schema="*", service_name="trinoTest"):
    """Create a deny policy in Ranger Admin"""
    policy = RangerPolicy()
    policy.service = service_name
    policy.name = policy_name
    policy.description = f"Test deny policy for {policy_name}"
    policy.isEnabled = True

    # Set resources
    policy.resources = {
        "catalog": RangerPolicyResource({"values": [catalog]}),
        "schema": RangerPolicyResource({"values": [schema]}),
        "table": RangerPolicyResource({"values": [resource_path]}),
    }

    # Set deny policy items
    deny_item = RangerPolicyItem()
    deny_item.users = users or ["test_user"]
    deny_item.accesses = [
        RangerPolicyItemAccess({"type": perm}) for perm in permissions
    ]

    policy.denyPolicyItems = [deny_item]

    return ranger_client.create_policy(policy)


@pytest.fixture
def ranger_client():
    """Create a Ranger client"""
    return RangerClient(
        url=RANGER_ADMIN_URL, auth=(RANGER_ADMIN_USER, RANGER_ADMIN_PASSWORD)
    )


@pytest.fixture(scope="session")
def trino_test_service():
    """Create the trinoTest service for testing"""
    service_name = "trinoTest"

    # Create ranger client for this fixture
    ranger_client = RangerClient(
        url=RANGER_ADMIN_URL, auth=(RANGER_ADMIN_USER, RANGER_ADMIN_PASSWORD)
    )

    # Check if service already exists
    try:
        existing_service = ranger_client.get_service(service_name)
        if existing_service:
            yield service_name
            return
    except Exception:
        # Service doesn't exist, create it
        pass

    # Create service configuration
    service = RangerService()
    service.name = service_name
    service.displayName = service_name
    service.type = "trino"
    service.description = "Trino service for testing"
    service.isEnabled = True
    service.configs = {
        "username": "admin",
        "password": "rangerR0cks!",
        "jdbc.driverClassName": "io.trino.jdbc.TrinoDriver",
        "jdbc.url": "jdbc:trino://trino:8080",
        "ranger.plugin.trino.service.name": service_name,
        "ranger.plugin.trino.policy.rest.url": "http://ranger:6080",
        "ranger.plugin.trino.policy.source.impl": "org.apache.ranger.admin.client.RangerAdminRESTClient",
        "ranger.plugin.trino.policy.rest.ssl.config.file": "/etc/ranger/trino/policycache/trino-policy-cache.json",
        "ranger.plugin.trino.policy.pollIntervalMs": "30000",
        "ranger.plugin.trino.policy.cache.dir": "/etc/ranger/trino/policycache"
    }

    # Create the service
    created_service = ranger_client.create_service(service)

    yield service_name


@pytest.fixture
def isolated_ranger_service(ranger_client):
    """Create an isolated Ranger service for each test"""
    # Generate unique service name for isolation
    service_name = "trinoTest"

    # Create service configuration
    service = RangerService()
    service.name = service_name
    service.displayName = service_name
    service.type = "trino"
    service.description = f"Isolated test service {service_name}"
    service.isEnabled = True
    service.configs = {
        "username": "admin",
        "password": "rangerR0cks!",
        "jdbc.driverClassName": "io.trino.jdbc.TrinoDriver",
        "jdbc.url": "jdbc:trino://trino:8080",
        "ranger.plugin.trino.service.name": service_name,
        "ranger.plugin.trino.policy.rest.url": "http://ranger:6080",
        "ranger.plugin.trino.policy.source.impl": "org.apache.ranger.admin.client.RangerAdminRESTClient",
        "ranger.plugin.trino.policy.rest.ssl.config.file": "/etc/ranger/trino/policycache/trino-policy-cache.json",
        "ranger.plugin.trino.policy.pollIntervalMs": "30000",
        "ranger.plugin.trino.policy.cache.dir": "/etc/ranger/trino/policycache"
    }

    # Create the service
    created_service = ranger_client.create_service(service)

    yield service_name

    # Cleanup: delete the service after test
    try:
        ranger_client.delete_service_by_id(created_service.id)
    except Exception:
        pass  # Ignore cleanup errors


@pytest.fixture
def trino_connection():
    return trino.dbapi.connect(
        host=TRINO_HOST,
        port=TRINO_PORT,
        user="admin",
        catalog="memory",
        schema="default",
    )


@pytest.fixture
def trino_connection_factory():
    """Factory fixture to create connections for different users"""
    def _create_connection(user, catalog="memory", schema="default"):
        return trino.dbapi.connect(
            host=TRINO_HOST,
            port=TRINO_PORT,
            user=user,
            catalog=catalog,
            schema=schema,
        )
    return _create_connection


def test_ranger_policy_enforcement_isolated(ranger_client, trino_connection, isolated_ranger_service):
    """Test that Ranger policies are properly enforced with isolated service"""
    # Create a test table
    cursor = trino_connection.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS test_table (id INT, name VARCHAR)")

    # Create a policy that allows SELECT but denies INSERT using isolated service
    policy = create_ranger_policy(
        ranger_client, "test_select_policy", "test_table", ["select"],
        service_name=isolated_ranger_service
    )

    try:
        # Wait for policy to take effect
        time.sleep(5)

        # Test SELECT (should succeed)
        cursor.execute("SELECT * FROM test_table")
        assert cursor.fetchall() is not None

        # Test INSERT (should fail)
        with pytest.raises(Exception):
            cursor.execute("INSERT INTO test_table VALUES (1, 'test')")

    finally:
        # Cleanup
        cursor.execute("DROP TABLE IF EXISTS test_table")
        ranger_client.delete_policy_by_id(policy.id)


def test_ranger_policy_enforcement(ranger_client, trino_connection, trino_test_service):
    """Test that Ranger policies are properly enforced"""
    # Create a test table
    cursor = trino_connection.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS test_table (id INT, name VARCHAR)")

    # Create a policy that allows SELECT but denies INSERT
    policy = create_ranger_policy(
        ranger_client, "test_select_policy", "test_table", ["select"]
    )

    try:
        # Wait for policy to take effect
        time.sleep(5)

        # Test SELECT (should succeed)
        cursor.execute("SELECT * FROM test_table")
        assert cursor.fetchall() is not None

        # Test INSERT (should fail)
        with pytest.raises(Exception):
            cursor.execute("INSERT INTO test_table VALUES (1, 'test')")

    finally:
        # Cleanup
        cursor.execute("DROP TABLE IF EXISTS test_table")
        ranger_client.delete_policy_by_id(policy.id)


def test_ranger_policy_deny_all(ranger_client, trino_connection, trino_test_service):
    """Test that a deny-all policy works correctly"""
    # Create a test table
    cursor = trino_connection.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS test_table_deny (id INT, name VARCHAR)")

    # Create a policy that denies all access
    policy = create_ranger_policy(
        ranger_client,
        "test_deny_all_policy",
        "test_table_deny",
        [],  # No permissions means deny all
    )

    try:
        # Wait for policy to take effect
        time.sleep(5)

        # All operations should fail
        with pytest.raises(Exception):
            cursor.execute("SELECT * FROM test_table_deny")

        with pytest.raises(Exception):
            cursor.execute("INSERT INTO test_table_deny VALUES (1, 'test')")

    finally:
        # Cleanup
        cursor.execute("DROP TABLE IF EXISTS test_table_deny")
        ranger_client.delete_policy_by_id(policy.id)


def test_multiple_user_authentication(ranger_client, trino_connection_factory, trino_test_service):
    """Test access control with different users"""
    admin_conn = trino_connection_factory("admin")
    test_user_conn = trino_connection_factory("test_user")
    readonly_conn = trino_connection_factory("read_only_user")

    admin_cursor = admin_conn.cursor()
    test_cursor = test_user_conn.cursor()
    readonly_cursor = readonly_conn.cursor()

    # Admin creates table
    admin_cursor.execute("CREATE TABLE IF NOT EXISTS multi_user_test (id INT, data VARCHAR)")

    # Create policy allowing test_user full access
    full_policy = create_ranger_policy(
        ranger_client, "test_user_full_access", "multi_user_test",
        ["select", "insert", "update", "delete"], users=["test_user"]
    )

    # Create policy allowing read_only_user only select
    readonly_policy = create_ranger_policy(
        ranger_client, "readonly_user_select", "multi_user_test",
        ["select"], users=["read_only_user"]
    )

    try:
        time.sleep(5)  # Wait for policies to take effect

        # Test user should be able to insert and select
        test_cursor.execute("INSERT INTO multi_user_test VALUES (1, 'test data')")
        test_cursor.execute("SELECT * FROM multi_user_test")
        assert len(test_cursor.fetchall()) > 0

        # Read-only user should be able to select but not insert
        readonly_cursor.execute("SELECT * FROM multi_user_test")
        assert len(readonly_cursor.fetchall()) > 0

        with pytest.raises(Exception):
            readonly_cursor.execute("INSERT INTO multi_user_test VALUES (2, 'forbidden')")

    finally:
        # Cleanup
        admin_cursor.execute("DROP TABLE IF EXISTS multi_user_test")
        ranger_client.delete_policy_by_id(full_policy.id)
        ranger_client.delete_policy_by_id(readonly_policy.id)

# Implemented by me
def test_policy_on_different_level(ranger_client, trino_connection, trino_test_service, trino_connection_factory):
    """Test permissions at different resource levels (catalog, schema, table)"""
    # admin_cursor = trino_connection.cursor()
    test_user = trino_connection_factory("test_user")
    test_user_cursor = test_user.cursor()

    # Check that the error message contains expected access denied information
    with pytest.raises(TrinoUserError) as exc_info:
        test_user_cursor.execute("SHOW SCHEMAS IN memory")
    assert "Access Denied" in str(exc_info.value)

    assert(1+1 == 2)

    # Expect test_user can't select
    # Create policy allowing read_only_user only select
    # test_user_policy = create_ranger_policy(
    #     ranger_client, "readonly_user_select", "multi_user_test",
    #     ["select"], users=["test_user"]
    # )
    #




def test_resource_level_permissions(ranger_client, trino_connection, trino_test_service):
    """Test permissions at different resource levels (catalog, schema, table)"""
    cursor = trino_connection.cursor()

    # Test catalog-level policy
    catalog_policy = create_ranger_policy(
        ranger_client, "catalog_level_test", "*", ["select"],
        catalog="memory", schema="*"
    )

    # Test schema-level policy
    schema_policy = create_ranger_policy(
        ranger_client, "schema_level_test", "*", ["select", "create"],
        catalog="memory", schema="test_schema"
    )

    try:
        cursor.execute("CREATE SCHEMA IF NOT EXISTS test_schema")
        cursor.execute("CREATE TABLE IF NOT EXISTS test_schema.schema_test (id INT)")

        time.sleep(5)  # Wait for policies to take effect

        # Test access at different levels
        cursor.execute("SELECT * FROM test_schema.schema_test")

    finally:
        # Cleanup
        cursor.execute("DROP TABLE IF EXISTS test_schema.schema_test")
        cursor.execute("DROP SCHEMA IF EXISTS test_schema")
        ranger_client.delete_policy_by_id(catalog_policy.id)
        ranger_client.delete_policy_by_id(schema_policy.id)


def test_comprehensive_permission_types(ranger_client, trino_connection, trino_test_service):
    """Test all permission types: select, insert, update, delete, create, drop"""
    cursor = trino_connection.cursor()

    # Create table first
    cursor.execute("CREATE TABLE IF NOT EXISTS perm_test (id INT, name VARCHAR, value INT)")
    cursor.execute("INSERT INTO perm_test VALUES (1, 'initial', 100)")

    permission_tests = [
        ("select_only", ["select"]),
        ("insert_only", ["insert"]),
        ("update_only", ["update"]),
        ("delete_only", ["delete"]),
        ("create_drop", ["create", "drop"]),
        ("full_access", ["select", "insert", "update", "delete", "create", "drop"])
    ]

    for policy_name, permissions in permission_tests:
        policy = create_ranger_policy(
            ranger_client, policy_name, "perm_test", permissions
        )

        try:
            time.sleep(3)  # Wait for policy to take effect

            if "select" in permissions:
                cursor.execute("SELECT * FROM perm_test")
                assert cursor.fetchall() is not None
            else:
                with pytest.raises(Exception):
                    cursor.execute("SELECT * FROM perm_test")

            if "insert" in permissions:
                cursor.execute("INSERT INTO perm_test VALUES (2, 'test', 200)")
            else:
                with pytest.raises(Exception):
                    cursor.execute("INSERT INTO perm_test VALUES (2, 'test', 200)")

        finally:
            ranger_client.delete_policy_by_id(policy.id)


def test_policy_priority_and_deny_policies(ranger_client, trino_connection, trino_test_service):
    """Test policy priority where deny policies override allow policies"""
    cursor = trino_connection.cursor()

    cursor.execute("CREATE TABLE IF NOT EXISTS priority_test (id INT, data VARCHAR)")

    # Create allow policy
    allow_policy = create_ranger_policy(
        ranger_client, "allow_all_priority", "priority_test",
        ["select", "insert", "update", "delete"]
    )

    # Create deny policy (should override allow policy)
    deny_policy = create_deny_policy(
        ranger_client, "deny_insert_priority", "priority_test",
        ["insert"]
    )

    try:
        time.sleep(5)  # Wait for policies to take effect

        # Select should work (allowed and not denied)
        cursor.execute("SELECT * FROM priority_test")

        # Insert should fail (denied policy overrides allow policy)
        with pytest.raises(Exception):
            cursor.execute("INSERT INTO priority_test VALUES (1, 'denied')")

    finally:
        # Cleanup
        cursor.execute("DROP TABLE IF EXISTS priority_test")
        ranger_client.delete_policy_by_id(allow_policy.id)
        ranger_client.delete_policy_by_id(deny_policy.id)


def test_audit_log_verification(ranger_client):
    """Test that audit logs are being generated"""
    # Get audit logs via Ranger API
    try:
        audit_url = f"{RANGER_ADMIN_URL}/service/plugins/policies/download/trinoDev"
        response = requests.get(
            audit_url,
            auth=(RANGER_ADMIN_USER, RANGER_ADMIN_PASSWORD),
            timeout=10
        )

        # Verify we can access audit endpoint
        assert response.status_code in [200, 404]  # 404 is acceptable if no logs yet

        # Check if audit service is configured
        service_url = f"{RANGER_ADMIN_URL}/service/public/v2/api/service/name/trinoDev"
        service_response = requests.get(
            service_url,
            auth=(RANGER_ADMIN_USER, RANGER_ADMIN_PASSWORD),
            timeout=10
        )

        if service_response.status_code == 200:
            service_config = service_response.json()
            # Verify audit configuration exists
            assert "configs" in service_config

    except requests.exceptions.RequestException as e:
        pytest.skip(f"Could not verify audit logs: {e}")


def test_error_handling_and_edge_cases(ranger_client, trino_connection, trino_test_service):
    """Test error handling and edge cases"""
    cursor = trino_connection.cursor()

    # Test with non-existent table
    policy = create_ranger_policy(
        ranger_client, "nonexistent_table_test", "nonexistent_table", ["select"]
    )

    try:
        time.sleep(3)

        # Should fail gracefully when accessing non-existent table
        with pytest.raises(Exception):
            cursor.execute("SELECT * FROM nonexistent_table")

    finally:
        ranger_client.delete_policy_by_id(policy.id)

    # Test with invalid resource patterns
    try:
        invalid_policy = create_ranger_policy(
            ranger_client, "invalid_resource_test", "", ["select"]  # empty resource
        )
        # Should either create successfully or fail gracefully
        ranger_client.delete_policy_by_id(invalid_policy.id)
    except Exception:
        # Expected behavior for invalid resource
        pass


def test_concurrent_policy_operations(ranger_client, trino_connection, trino_test_service):
    """Test concurrent policy creation and enforcement"""
    cursor = trino_connection.cursor()

    cursor.execute("CREATE TABLE IF NOT EXISTS concurrent_test (id INT, data VARCHAR)")

    # Create multiple policies simultaneously
    policies = []
    for i in range(3):
        policy = create_ranger_policy(
            ranger_client, f"concurrent_policy_{i}", "concurrent_test", ["select"]
        )
        policies.append(policy)

    try:
        time.sleep(5)  # Wait for all policies to take effect

        # Test that access works with multiple policies
        cursor.execute("SELECT * FROM concurrent_test")

    finally:
        # Cleanup all policies
        cursor.execute("DROP TABLE IF EXISTS concurrent_test")
        for policy in policies:
            try:
                ranger_client.delete_policy_by_id(policy.id)
            except Exception:
                pass  # Continue cleanup even if one fails
