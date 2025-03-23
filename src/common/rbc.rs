/// This file contains more common reliable broadcast protocols used in MPC.
/// You can reuse them in your own custom MPC protocol implementations.

/// CommonSubset is a subroutine used to implement many RBC protocols.
/// It is used to determine which RBC instances have terminated.
trait CommonSubset {

}

struct Bracha {}

struct AVID {}

impl RBC for Bracha {

}

impl RBC for AVID {
    
}