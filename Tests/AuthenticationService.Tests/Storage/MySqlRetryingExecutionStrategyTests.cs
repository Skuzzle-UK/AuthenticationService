using System.Data.Common;
using AuthenticationService.Storage;
using AwesomeAssertions;

// The two fakes below are declared in the MySqlConnector and MySql.Data.MySqlClient
// namespaces so their Type.FullName starts with the prefix the predicate matches on,
// without needing a reference on the real provider assemblies.
using MySqlConnectorFake = MySqlConnector.FakeMySqlException;
using MySqlDataFake = MySql.Data.MySqlClient.FakeMySqlException;

namespace AuthenticationService.Tests.Storage
{
    /// <summary>
    /// Covers the IsTransientDatabaseError predicate. The retry loop itself is the
    /// EF Core base class's job and isn't re-tested here.
    /// </summary>
    public class MySqlRetryingExecutionStrategyTests
    {
        [Fact]
        public void DbException_IsTransient()
        {
            MySqlRetryingExecutionStrategy.IsTransientDatabaseError(
                new TestDbException("connection lost")).Should().BeTrue();
        }

        [Fact]
        public void TimeoutException_IsTransient()
        {
            MySqlRetryingExecutionStrategy.IsTransientDatabaseError(
                new TimeoutException("query timed out")).Should().BeTrue();
        }

        [Fact]
        public void MySqlConnectorNamespace_IsTransient()
        {
            var ex = new MySqlConnectorFake("deadlock");
            ex.GetType().FullName.Should().StartWith("MySqlConnector.");
            MySqlRetryingExecutionStrategy.IsTransientDatabaseError(ex).Should().BeTrue();
        }

        [Fact]
        public void MySqlDataNamespace_IsTransient()
        {
            var ex = new MySqlDataFake("lock wait timeout");
            ex.GetType().FullName.Should().StartWith("MySql.Data.");
            MySqlRetryingExecutionStrategy.IsTransientDatabaseError(ex).Should().BeTrue();
        }

        [Fact]
        public void TransientCauseInInnerException_IsTransient()
        {
            // EF Core wraps provider exceptions — walker has to dig in to find the cause.
            var wrapped = new InvalidOperationException("EF wrapper", new TestDbException("server has gone away"));
            MySqlRetryingExecutionStrategy.IsTransientDatabaseError(wrapped).Should().BeTrue();
        }

        [Fact]
        public void TransientCauseTwoLevelsDeep_IsTransient()
        {
            var inner = new TimeoutException("timeout");
            var middle = new InvalidOperationException("middle", inner);
            var outer = new ApplicationException("outer", middle);
            MySqlRetryingExecutionStrategy.IsTransientDatabaseError(outer).Should().BeTrue();
        }

        [Fact]
        public void NonDbException_IsNotTransient()
        {
            MySqlRetryingExecutionStrategy.IsTransientDatabaseError(
                new InvalidOperationException("bad call")).Should().BeFalse();
        }

        [Fact]
        public void DeepChainWithNoMatch_IsNotTransient()
        {
            var outer = new ApplicationException("outer",
                new InvalidOperationException("middle",
                    new ArgumentException("inner")));
            MySqlRetryingExecutionStrategy.IsTransientDatabaseError(outer).Should().BeFalse();
        }

        // DbException is abstract — need a concrete subclass to instantiate one.
        private sealed class TestDbException : DbException
        {
            public TestDbException(string message) : base(message) { }
        }
    }
}

namespace MySqlConnector
{
    internal sealed class FakeMySqlException : Exception
    {
        public FakeMySqlException(string message) : base(message) { }
    }
}

namespace MySql.Data.MySqlClient
{
    internal sealed class FakeMySqlException : Exception
    {
        public FakeMySqlException(string message) : base(message) { }
    }
}
