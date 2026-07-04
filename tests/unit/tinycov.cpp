#include <catch2/catch_test_macros.hpp>
#include <tinykvm/machine.hpp>
#include <tinycov/tinycov.hpp>

extern std::vector<uint8_t> build_and_load(const std::string& code);
static const uint64_t MAX_MEMORY = 8ul << 20; /* 8MB */
static const std::vector<std::string> env {
	"LC_TYPE=C", "LC_ALL=C", "USER=root"
};

TEST_CASE("Initialize KVM", "[tinycov]")
{
	tinykvm::Machine::init();
}

TEST_CASE("Coverage collection", "[tinycov]")
{
	const auto binary = build_and_load(R"M(
int main() {
	int a = 1;
    if (a == 1) {
        return 666;
    }
	return 0;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
    machine.setup_linux({"tinycov_test"}, env);

    tinycov::CoverageMachine cov(machine);
    cov.install_hooks();

	machine.run(2.0f);

	REQUIRE(machine.return_value() == 666);
    REQUIRE(cov.coverage_count() > 0);
}
