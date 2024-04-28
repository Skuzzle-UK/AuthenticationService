using AutoMapper;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Authentication.Service.Storage.Entities;

namespace Skuzzle.Core.Authentication.Service;

public class MappingProfiles : Profile
{
    public MappingProfiles()
    {
        CreateMap<User, UserEntity>()
            .ReverseMap();
    }
}
