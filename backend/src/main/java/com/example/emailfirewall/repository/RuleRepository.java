package com.example.emailfirewall.repository;

import com.example.emailfirewall.entity.RuleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.UUID;

public interface RuleRepository extends JpaRepository<RuleEntity, UUID> {

}
