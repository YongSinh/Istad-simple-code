package co.istad.app.service;

import co.istad.app.entity.Book;

import java.util.List;

public interface BookService {

    List<Book> findAll();

    void deleteBookByStatus(Boolean status);

}
