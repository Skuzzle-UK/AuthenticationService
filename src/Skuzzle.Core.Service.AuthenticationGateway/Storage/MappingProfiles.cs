using AutoMapper;
using Skuzzle.Core.Service.AuthenticationGateway.Models;
using Skuzzle.Core.Service.AuthenticationGateway.Storage.Entities;

namespace Skuzzle.Core.Service.AuthenticationGateway.Storage;

public class MappingProfiles : Profile
{
    public MappingProfiles()
    {
        CreateMap<User, UserEntity>()
            .ReverseMap();
    }
}
