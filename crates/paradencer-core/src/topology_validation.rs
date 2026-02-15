use crate::TopologySpec;
use std::collections::HashSet;

impl TopologySpec {
    pub fn validate(&self) -> Result<(), String> {
        if self.stages.is_empty() {
            return Err("topology must contain at least one stage".to_string());
        }

        let mut stage_ids = HashSet::new();
        for stage in &self.stages {
            if stage.stage_id.trim().is_empty() {
                return Err("stage_id must not be empty".to_string());
            }
            if !stage_ids.insert(stage.stage_id.clone()) {
                return Err(format!("duplicate stage_id '{}'", stage.stage_id));
            }
        }

        let mut link_ids = HashSet::new();
        for link in &self.links {
            if link.link_id.trim().is_empty() {
                return Err("link_id must not be empty".to_string());
            }
            if !link_ids.insert(link.link_id.clone()) {
                return Err(format!("duplicate link_id '{}'", link.link_id));
            }
            if link.capacity == 0 {
                return Err(format!("link '{}' has zero capacity", link.link_id));
            }
            if !stage_ids.contains(&link.source_stage_id) {
                return Err(format!(
                    "link '{}' references unknown source stage '{}'",
                    link.link_id, link.source_stage_id
                ));
            }
            if !stage_ids.contains(&link.destination_stage_id) {
                return Err(format!(
                    "link '{}' references unknown destination stage '{}'",
                    link.link_id, link.destination_stage_id
                ));
            }
        }

        Ok(())
    }
}
