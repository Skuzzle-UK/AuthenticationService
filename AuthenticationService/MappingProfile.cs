using AuthenticationService.Dtos;
using AuthenticationService.Entities;
using AutoMapper;

namespace AuthenticationService;

public class MappingProfile : Profile
{
    public MappingProfile()
    {
        CreateMap<UserRegistrationDto, User>();
    }
}
