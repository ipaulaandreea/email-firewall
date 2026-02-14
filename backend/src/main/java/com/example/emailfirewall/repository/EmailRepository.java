package com.example.emailfirewall.repository;
import com.example.emailfirewall.entity.EmailEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.UUID;

public interface EmailRepository extends JpaRepository<EmailEntity, UUID> {

}
