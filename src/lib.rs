use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128, Block,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub enum Enemy {
    Cruiser,
    Spaceship,
    Asteroid, 
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct ScoreEvent {
    time: f32, 
    enemy: Enemy, 
    pos: (f32, f32)
}

impl ScoreEvent {
    pub fn get_score(&self) -> u32 {
        match self.enemy {
            Enemy::Cruiser => 100,
            Enemy::Spaceship => 200,
            Enemy::Asteroid => 50, 
        }
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidPadding,
    SerializationError(rmp_serde::decode::Error),
}

impl From<rmp_serde::decode::Error> for Error {
    fn from(err: rmp_serde::decode::Error) -> Self {
        Error::SerializationError(err)
    }
}

#[derive(Debug, Clone)]
pub struct ScoreSubmission(Vec<u8>);

impl ScoreSubmission {
    pub fn to_buffer(self) -> Vec<u8> {
        self.0
    }

    pub fn from_buffer(buffer: Vec<u8>) -> Self {
        Self(buffer)
    }

    pub fn from_data(data: &[ScoreEvent], encryption_key: &[u8; 16]) -> Result<Self, Error> {
        // This should never fail
        let encoded = rmp_serde::to_vec(data).expect("Failed to encode score data");

        // Add PKCS5 Padding
        let padding: u8 = 16 - encoded.len() as u8 % 16 as u8;
        let mut blocks: Vec<Block> = encoded
            .chunks(16)
            .map(|block| {
                let mut block = block.to_vec();
                block.resize(16, padding);
                Block::clone_from_slice(&block)
            })
            .collect();

        let key = GenericArray::from(*encryption_key);

        let cipher = Aes128::new(&key);

        cipher.encrypt_blocks(&mut blocks);
        Ok(Self(Vec::from_iter(
            blocks.iter().flat_map(|block| block.iter().cloned()),
        )))
    }

    pub fn to_data(&self, encryption_key: &[u8; 16]) -> Result<Vec<ScoreEvent>, Error> {
        let key = GenericArray::from(*encryption_key);
        let cipher = Aes128::new(&key);

        let mut blocks: Vec<Block> = self
            .0
            .chunks(16)
            .map(|block| Block::clone_from_slice(&block))
            .collect();

        cipher.decrypt_blocks(&mut blocks);

        let mut data = Vec::from_iter(blocks.iter().flat_map(|block| block.iter().cloned()));

        let padding = *data.last().ok_or(Error::InvalidPadding)?;

        data.truncate(data.len() - padding as usize);

        Ok(rmp_serde::from_slice(&data)?)
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_score_submission() {
        let key = [42u8; 16];
        let events = vec![
            ScoreEvent {
                time: 0.0,
                enemy: Enemy::Cruiser,
                pos: (0.0, 0.0),
            },
            ScoreEvent {
                time: 1.0,
                enemy: Enemy::Spaceship,
                pos: (1.0, 1.0),
            },
            ScoreEvent {
                time: 2.0,
                enemy: Enemy::Asteroid,
                pos: (2.0, 2.0),
            },
        ];

        let submission = ScoreSubmission::from_data(&events, &key).unwrap();

        let data = submission.to_data(&key).unwrap();
        assert_eq!(data, events);
    }
}
