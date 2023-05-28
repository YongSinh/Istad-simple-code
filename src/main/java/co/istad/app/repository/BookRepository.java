package co.istad.app.repository;

import co.istad.app.entity.Book;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface BookRepository extends CrudRepository<Book, UUID> {

    List<Book> findByTitleStartingWithIgnoreCaseOrderByStatusDesc(String title);
    List<Book> findByTitleContainingIgnoreCase(String title);

    @Query("SELECT b FROM e_book b WHERE b.author = ?1")
    List<Book> selectBookByAuthorName(String name);

    @Query("SELECT b FROM e_book b WHERE b.uuid = ?1")
    Optional<Book> selectBookByPrimaryKey(UUID primaryKey);

    @Modifying
    @Query("DELETE FROM e_book b WHERE b.status = ?1")
    void deleteBookByStatus(Boolean status);

}
