package ie.atu.ids_service.repository;

import ie.atu.ids_service.model.Alert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AlertRepository extends JpaRepository<Alert, Long> {
List<Alert> findByUsername(String username);
}
