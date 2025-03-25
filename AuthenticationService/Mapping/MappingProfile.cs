using AuthenticationService.Shared.Dtos;
using AuthenticationService.Entities;
using AutoMapper;

namespace AuthenticationService.Mapping;

public class MappingProfile : Profile
{
    public MappingProfile()
    {
        CreateMap<RegistrationDto, User>();
    }
}
