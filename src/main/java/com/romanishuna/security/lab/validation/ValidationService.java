package com.romanishuna.security.lab.validation;

import com.romanishuna.security.lab.exception.BadRequestException;
import org.springframework.stereotype.Service;

import java.util.regex.Pattern;

@Service
public class ValidationService {


    private static final int MIN_PASSWORD_LENGTH = 10;
    private static final int MAX_PASSWORD_LENGTH = 30;

    private static final int MIN_UPPER_CASE_LETTERS = 2;
    private static final int MIN_LOWER_CASE_LETTERS = 2;
    private static final int MIN_SPECIAL_CHARACTERS = 1;
    private static final int MIN_DIGITS = 2;

    private static final int MAX_REPEATING_CHARACTERS = 3;

    private static final String CONSECUTIVE_NUMBERS = "01234567890";
    private static final String CONSECUTIVE_NUMBERS_REVERSE = new StringBuilder(CONSECUTIVE_NUMBERS).reverse().toString();

    private static final String KEYBOARD_CONSECUTIVE_LETTERS = "qwertyuiopasdfghjklzxcvbnm";
    private static final String KEYBOARD_CONSECUTIVE_LETTERS_REVERSE = new StringBuilder(KEYBOARD_CONSECUTIVE_LETTERS).reverse().toString();

    private static final String ENGLISH_ALPHABET = "abcdefghijklmnopqrstuvwxyz";
    private static final String ENGLISH_ALPHABET_REVERSED = "zyxwvutsrqponmlkjihgfedcba";

    private static final String ALLOWED_SPECIAL_CHARS = "/*!@#$%^&*(){}_[]|?<>,.";

    private static final Pattern emailPattern = Pattern.compile("^[a-zA-Z0-9_!#$%&’*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+$");

    public void validateEmail(String email) {
        if(!emailPattern.matcher(email).matches()) {
            throw new BadRequestException("Email: " + email + " is not valid");
        }
    }


    public void validatePassword(String password, String email) {
        if (password.length() < MIN_PASSWORD_LENGTH) {
            throw new BadRequestException("Password is too small, min: " + MIN_PASSWORD_LENGTH);
        }
        if (password.length() > MAX_PASSWORD_LENGTH) {
            throw new BadRequestException("Password is too big, max: " + MAX_PASSWORD_LENGTH);
        }

        char[] passwordArray = password.toCharArray();
        int upperLetterCount = 0;
        int lowerLettersCount = 0;
        int specialCharacterCount = 0;
        int digitCount = 0;
        for (char value : passwordArray) {
            if (Character.isLowerCase(value)) {
                lowerLettersCount++;
                continue;
            }
            if (Character.isUpperCase(value)) {
                upperLetterCount++;
                continue;
            }
            if (Character.isDigit(value)) {
                digitCount++;
                continue;
            }
            if (ALLOWED_SPECIAL_CHARS.contains(String.valueOf(value))) {
                specialCharacterCount++;
                continue;
            }
            throw new BadRequestException("Password contains prohibited characters.");
        }

        if (upperLetterCount < MIN_UPPER_CASE_LETTERS) {
            throw new BadRequestException("Password should have at least " + MIN_UPPER_CASE_LETTERS + " upper case letters.");
        }

        if (lowerLettersCount < MIN_LOWER_CASE_LETTERS) {
            throw new BadRequestException("Password should have at least " + MIN_LOWER_CASE_LETTERS + " lower case letters.");
        }

        if (digitCount < MIN_DIGITS) {
            throw new BadRequestException("Password should have at least " + MIN_DIGITS + " digits.");
        }

        if (specialCharacterCount < MIN_SPECIAL_CHARACTERS) {
            throw new BadRequestException("Password should have at least " + MIN_SPECIAL_CHARACTERS + " special character.");
        }

        for (char c : passwordArray) {
            int count = 0;
            for (char letter : passwordArray) {
                if (c == letter) {
                    count++;
                }
            }
            if (count > MAX_REPEATING_CHARACTERS) {
                throw new BadRequestException("Password can't contain more then " + MAX_REPEATING_CHARACTERS + " same characters.");
            }
        }

        String lowerCasePassword = password.toLowerCase();
        for (int i = 0; i < KEYBOARD_CONSECUTIVE_LETTERS.length() - 3; i++) {
            if (lowerCasePassword.contains(KEYBOARD_CONSECUTIVE_LETTERS.substring(i, i + 4)) ||
                    lowerCasePassword.contains(KEYBOARD_CONSECUTIVE_LETTERS_REVERSE.substring(i, i + 4))) {
                throw new BadRequestException("Password can't contain more than 3 keyboard consecutive letters.");
            }
        }

        for (int i = 0; i < CONSECUTIVE_NUMBERS.length() - 3; i++) {
            if (password.contains(CONSECUTIVE_NUMBERS.substring(i, i + 4)) || password.contains(CONSECUTIVE_NUMBERS_REVERSE.substring(i, i + 4))) {
                throw new BadRequestException("Password can't contain than 3 consecutive numbers.");
            }
        }

        String emailPart = email.split("@")[0].toLowerCase();
        for (int i = 0; i < emailPart.length() - 3; i++) {
            if (lowerCasePassword.contains(emailPart.substring(i, i + 4))) {
                throw new BadRequestException("Password should not contain parts of an email.");
            }
        }

        String splitPassword;
        for (int i = 0; i < password.length() - 3; i++) {
            splitPassword = (password.substring(0, i) + password.substring(i + 4)).toLowerCase();
            if (splitPassword.contains(password.substring(i, i + 4).toLowerCase())) {
                throw new BadRequestException("Password should not contain repeating parts.");
            }
        }
    }
}
