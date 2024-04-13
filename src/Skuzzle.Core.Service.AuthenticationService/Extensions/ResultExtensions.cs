using Skuzzle.Core.Service.AuthenticationService.Models;

namespace Skuzzle.Core.Service.AuthenticationService.Extensions;

public static class ResultExtensions
{
    public static Result OnSuccess(this Result result, Func<Result> func)
    {
        if (result.IsFailure)
            return result;

        return func();
    }

    public static Result OnSuccess(this Result result, Action action)
    {
        if (result.IsFailure)
            return result;

        action();

        return Result.Ok();
    }

    public static Result OnSuccess<T>(this Result<T> result, Action<T> action)
    {
        if (result.IsFailure)
            return result;

        action(result.Value);

        return Result.Ok();
    }

    public static Result<T> OnSuccess<T>(this Result result, Func<T> func)
    {
        if (result.IsFailure)
            return Result.Fail<T>(result.ErrorMessage);

        return Result.Ok(func());
    }

    public static Result<T> OnSuccess<T>(this Result result, Func<Result<T>> func)
    {
        if (result.IsFailure)
            return Result.Fail<T>(result.ErrorMessage);

        return func();
    }

    public static Result OnSuccess<T>(this Result<T> result, Func<T, Result> func)
    {
        if (result.IsFailure)
            return result;

        return func(result.Value);
    }

    public static Result OnFailure(this Result result, Action action)
    {
        if (result.IsFailure)
        {
            action();
        }

        return result;
    }

    public static Result OnBoth(this Result result, Action<Result> action)
    {
        action(result);

        return result;
    }

    public static T OnBoth<T>(this Result result, Func<Result, T> func) => func(result);
}