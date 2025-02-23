﻿using FluentValidation;
using Microsoft.EntityFrameworkCore;
using Skuzzle.Core.Authentication.Lib.Dtos;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Authentication.Service.Storage;

namespace Skuzzle.Core.Authentication.Service.Validators;

public class UserDtoValidator : AbstractValidator<UserDto>
{
    private readonly IRepository<User> _repository;

    public UserDtoValidator(IRepository<User> repository)
    {
        _repository = repository;

        RuleFor(x => x.Username)
            .NotEmpty()
            .WithMessage("Username can not be empty");
        
        RuleFor(x => x.Username)
            .MinimumLength(4)
            .WithMessage("Username must be longer than 4 characters");
        
        RuleFor(x => x.Username)
            .MaximumLength(25)
            .WithMessage("Username must be shorter than 25 characters");
        
        RuleFor(x => x.Username)
            .MustAsync(async (username, ct) =>
            {
                var result = await _repository.FirstOrDefaultAsync(o => o.Username.ToLower() == username.ToLower(), ct);

                if (result.IsSuccess)
                {
                    return result.Value == null;
                }
                return true;
            })
            .WithMessage("Username is already in use. Please try something different.");

        RuleFor(x => x.Password)
            .Matches(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$")
            .WithMessage("Your password must contain at least one uppercase letter, one lowercase letter, one number and one special character and be at least 8 characters long.");

        RuleFor(x => x.Email)
            .EmailAddress()
            .WithMessage("Email address must be a valid email address");

        RuleFor(x => x.Email)
            .MaximumLength(320)
            .WithMessage("Email address must be less than 320 characters");

        RuleFor(x => x.Email)
            .MustAsync(async (email, ct) =>
            {
                var result = await _repository.FirstOrDefaultAsync(o => o.Email.ToLower() == email.ToLower(), ct);
                if (result.IsSuccess)
                {
                    return result.Value == null;
                }
                return true;
            })
            .WithMessage("A user with that email address is already registered");

        RuleFor(x => x.FirstName)
            .MaximumLength(128)
            .WithMessage("FirstName must be shorter than 128 characters");

        RuleFor(x => x.LastName)
            .MaximumLength(128)
            .WithMessage("LastName must be shorter than 128 characters");

        RuleFor(x => x.Phone)
            .Matches(@"^(?:(?:\+1\s*\d{10})|(?:\+44\s*\d{10})|(?:00\s*44\s*\d{10})|(?:\+3\d{1,2}\s*\d{5,10})|(?:00\d{11,15})|(?:\d{11}))?$")
            .WithMessage("This doesn't look like a valid phone number. Please try removing any spaces or non numerical characters");

        RuleFor(x => x.Country)
            .MaximumLength(128)
            .WithMessage("Country must be shorter than 128 characters");
    }
}
