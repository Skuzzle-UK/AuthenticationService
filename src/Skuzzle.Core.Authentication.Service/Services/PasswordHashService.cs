﻿using Skuzzle.Core.Authentication.Lib.Dtos;
using Skuzzle.Core.Authentication.Lib.Models;
using System.Security.Cryptography;

namespace Skuzzle.Core.Authentication.Service.Extensions;

public class PasswordHashService : IPasswordHashService
{
    public (byte[] hash, byte[] salt) Create(string password)
    {
        using var hmac = new HMACSHA512();
        var salt = hmac.Key;
        var hash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));

        return (hash, salt);
    }

    public bool Verify(UserCredentialsDto userDto, User user)
    {
        using var hmac = new HMACSHA512(user.Salt);
        var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(userDto.Password));
        return computedHash.SequenceEqual(user.Hash);
    }
}