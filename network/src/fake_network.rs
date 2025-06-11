use crate::{Network, Node};

pub struct FakeNetwork;

impl<N: Node> Network<N> for FakeNetwork {
    fn send(
        &self,
        recipient: crate::PartyId,
        message: impl crate::Message,
    ) -> Result<usize, crate::NetworkError> {
        todo!()
    }

    fn broadcast(&self, message: impl crate::Message) -> Result<usize, crate::NetworkError> {
        todo!()
    }

    fn parties(&self) -> Vec<N> {
        todo!()
    }
}
