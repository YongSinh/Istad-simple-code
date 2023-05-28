package co.istad.app;

import co.istad.app.entity.Book;
import co.istad.app.repository.BookRepository;
import co.istad.app.repository.UserRepository;
import co.istad.app.service.BookService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.List;
import java.util.UUID;

@SpringBootApplication
public class Sp4JwtJpaApplication implements CommandLineRunner {

    public static void main(String[] args) {
        SpringApplication.run(Sp4JwtJpaApplication.class, args);
    }

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BookRepository bookRepository;

    @Override
    public void run(String... args) throws Exception {

        System.out.println(userRepository.findByEmail("it.chhaya@gmail.com"));

        Book book = new Book();
        book.setTitle("The lord of the Ring");
        book.setAuthor("ISTAD");
        book.setStatus(true);
        bookRepository.save(book);


        /*Book updateBook = new Book();
        updateBook.setUuid(UUID.fromString("b063103c-5dac-4db8-a9d2-f9bf44867095"));
        updateBook.setTitle("FastX");
        repository.save(updateBook);*/

//        System.out.println(repository.findById(UUID.fromString("b063103c-5dac-4db8-a9d2-f9bf44867095")));
//        System.out.println(repository.findByTitleContainingIgnoreCase("fast"));
//        System.out.println(repository.findByTitleStartingWithIgnoreCaseOrderByStatusDesc("a"));


        /*repository.deleteById(UUID.fromString("853c2a3d-da24-4b36-969e-8c7dc0ee1144"));
        System.out.println(repository.existsById(UUID.fromString("853c2a3d-da24-4b36-969e-8c7dc0ee1144")));*/

        /*List<Book> books = repository.selectBookByAuthorName("ISTAD");
        books.forEach(System.out::println);

        Book bookByPK = repository.selectBookByPrimaryKey(
                UUID.fromString("b063103c-5dac-4db8-a9d2-f9bf44867095")
        ).get();

        System.out.println(bookByPK);

        service.deleteBookByStatus(false);*/

    }

}
