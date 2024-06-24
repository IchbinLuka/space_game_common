use aes::{cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit}, Aes128, Block};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub enum Enemy {
    Cruiser, 
    Spaceship, 
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub enum ScoreEvent {
    EnemyKilled {
        enemy: Enemy, 
        pos: (f32, f32), 
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


pub struct ScoreSubmission(Vec<u8>);

impl ScoreSubmission {
    pub fn from_buffer(buffer: Vec<u8>) -> Self {
        Self(buffer)
    }

    pub fn from_data(data: &[ScoreEvent], encryption_key: &[u8; 16]) -> Result<Self, Error> {
        // This should never fail
        let encoded = rmp_serde::to_vec(data).expect("Failed to encode score data");
        
        // Add PKCS5 Padding
        let padding: u8 = 16 - encoded.len() as u8 % 16 as u8;
        let mut blocks: Vec<Block> = encoded.chunks(16).map(|block| {
            let mut block = block.to_vec();
            block.resize(16, padding);
            Block::clone_from_slice(&block)
        }).collect();

        let key = GenericArray::from(*encryption_key);

        let cipher = Aes128::new(&key);

        cipher.encrypt_blocks(&mut blocks);
        Ok(Self(Vec::from_iter(blocks.iter().flat_map(|block| block.iter().cloned()))))
    }

    pub fn to_data(&self, encryption_key: &[u8; 16]) -> Result<Vec<ScoreEvent>, Error> {
        let key = GenericArray::from(*encryption_key);
        let cipher = Aes128::new(&key);

        let mut blocks: Vec<Block> = self.0.chunks(16).map(|block| {
            Block::clone_from_slice(&block)
        }).collect();

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
            ScoreEvent::EnemyKilled {
                enemy: Enemy::Cruiser,
                pos: (1.0, 2.0),
            }, 
            ScoreEvent::EnemyKilled {
                enemy: Enemy::Spaceship,
                pos: (3.0, 4.0),
            }, 
            ScoreEvent::EnemyKilled {
                enemy: Enemy::Cruiser,
                pos: (5.0, 6.0),
            }, 
        ];

        let submission = ScoreSubmission::from_data(&events, &key).unwrap();

        let data = submission.to_data(&key).unwrap();
        assert_eq!(data, events);
    }
}