package cn.fatalc.catched.model

data class Check(
    val id: String,
    val group: String,
    val name: String,
    val description: String,
    val tags: Set<String> = emptySet(),
    val expected: String? = null,
    val run: () -> CheckResult
)

data class CheckResult(
    val detected: Boolean,
    val evidence: String? = null,
    val actual: String? = null
)
