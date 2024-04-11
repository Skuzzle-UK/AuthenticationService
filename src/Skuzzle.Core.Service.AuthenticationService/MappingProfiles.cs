using AutoMapper;
using Skuzzle.Core.Service.AuthenticationService.Models;
using Skuzzle.Core.Service.AuthenticationService.Storage.Entities;

namespace Skuzzle.Core.Service.AuthenticationService;

public class MappingProfiles : Profile
{
    public MappingProfiles()
    {
        CreateMap<User, UserEntity>()
            .ReverseMap();
    }
}
