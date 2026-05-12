package medviet.data_access

import future.keywords.if
import future.keywords.in

default allow := false
default deny := false

allow if {
    not deny
    input.user.role == "admin"
}

allow if {
    not deny
    input.user.role == "ml_engineer"
    input.resource in {"training_data", "model_artifacts"}
    input.action in {"read", "write"}
}

allow if {
    not deny
    input.user.role == "data_analyst"
    input.resource == "aggregated_metrics"
    input.action == "read"
}

allow if {
    not deny
    input.user.role == "data_analyst"
    input.resource == "reports"
    input.action == "write"
}

allow if {
    not deny
    input.user.role == "intern"
    input.resource == "sandbox_data"
    input.action in {"read", "write"}
}

deny if {
    input.user.role == "ml_engineer"
    input.resource == "production_data"
    input.action == "delete"
}

deny if {
    input.data_classification == "restricted"
    input.destination_country != "VN"
}
